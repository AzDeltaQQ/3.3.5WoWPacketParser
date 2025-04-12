import sys
import frida
import time
import json # Added json import
import re # Moved import here
import os # <<< Added os import
from collections import deque # Import deque
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                             QTextEdit, QPushButton, QHBoxLayout, QLineEdit, QLabel)
from PyQt6.QtCore import pyqtSignal, QObject, QThread, pyqtSlot, QTimer, QEventLoop # Import QTimer and QEventLoop

# (Or reorganize into a shared library later)
PROCESS_NAME = "Wow.exe" 
INIT_CRYPTO_HOOK_ADDRESS = 0x466BF0
ARC4_ENCRYPT_HOOK_ADDRESS = 0x774EA0
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) # <<< Get script directory
OPCODES_FILE_PATH = os.path.join(SCRIPT_DIR, "Opcodes.h") # <<< Relative path
SEND_STATE_OFFSET_CONST = 0x148
RECV_STATE_OFFSET_CONST = 0x24A

# Opcode Loading Logic
smsg_opcodes = {}
cmsg_opcodes = {}
try:
    opcode_regex = re.compile(r'^\s*(?!//)\s*([CSU]?MSG_\w+)\s*=\s*(0x[0-9a-fA-F]+).*$', re.IGNORECASE)
    with open(OPCODES_FILE_PATH, 'r') as f:
        for line in f:
            match = opcode_regex.match(line)
            if match:
                name = match.group(1)
                value_str = match.group(2)
                try:
                    value = int(value_str, 16)
                    if name.startswith("SMSG_"):
                        smsg_opcodes[value] = name
                    elif name.startswith("CMSG_"):
                        cmsg_opcodes[value] = name
                except ValueError:
                    print(f"Warning: Could not parse hex value: {line.strip()}")
    print(f"Loaded {len(smsg_opcodes)} SMSG and {len(cmsg_opcodes)} CMSG opcodes.")
    if not smsg_opcodes and not cmsg_opcodes:
        print("Warning: Opcodes failed to load.")
except FileNotFoundError:
    print(f"Error: Opcodes file not found at {OPCODES_FILE_PATH}")
    smsg_opcodes = {} # Ensure dicts exist even if file not found
    cmsg_opcodes = {}
except Exception as e:
    print(f"Error reading opcodes file: {e}")
    smsg_opcodes = {} 
    cmsg_opcodes = {}

# Frida Script
javascript_code = f"""
'use strict';

let smsgOpcodesDict = {{}};
let cmsgOpcodesDict = {{}};

recv('opcodes', function (value) {{
    send({{ type: 'log', payload: '[JS INFO] Handler opcodes invoked.' }});
    try {{
        smsgOpcodesDict = value.payload.smsg;
        cmsgOpcodesDict = value.payload.cmsg;
        send({{ type: 'log', payload: `    [JS INFO] Loaded ${{Object.keys(smsgOpcodesDict).length}} SMSG and ${{Object.keys(cmsgOpcodesDict).length}} CMSG opcodes.`}});
    }} catch (e) {{
        send({{ type: 'error', payload: 'JS Error processing opcodes: ' + e }});
    }}
}});

// Keep test message handler for now if needed for debugging
recv('test_message', function(value) {{
    send({{ type: 'log', payload: '[JS INFO] Received Test Message: ' + value.payload }});
}});

const initCryptoAddr = ptr("{hex(INIT_CRYPTO_HOOK_ADDRESS)}");
const arc4EncryptAddr = ptr("{hex(ARC4_ENCRYPT_HOOK_ADDRESS)}");

const SEND_STATE_OFFSET = {hex(SEND_STATE_OFFSET_CONST)};
const RECV_STATE_OFFSET = {hex(RECV_STATE_OFFSET_CONST)};

let sendStateAddr = null;
let recvStateAddr = null;
let cryptoBaseAddr = null;

// Helper function for sending buffer as hex string
function sendHex(buffer, count) {{ 
    try {{
        if (!buffer) return 'null';
        const maxLen = Math.min(buffer.byteLength || count || 64, count || 64); 
        let B = (buffer instanceof ArrayBuffer) ? new Uint8Array(buffer) : new Uint8Array(buffer.readByteArray(maxLen));
        let hex = '';
        for (let i = 0; i < B.length; i++) {{ 
            let byte = B[i];
            hex += ('00' + byte.toString(16)).slice(-2);
        }}
        return hex;
    }} catch (e) {{
        send({{ type: 'error', payload: 'JS Error in sendHex: ' + e }});
        return 'Hex Error';
    }}
}}

// --- Hook to Find Crypto States ---
Interceptor.attach(initCryptoAddr, {{ 
    onEnter: function(args) {{ 
        this.captured_base_ptr = this.context.ecx;
    }}, 
    onLeave: function(retval) {{ 
        cryptoBaseAddr = this.captured_base_ptr;
        if (!cryptoBaseAddr || cryptoBaseAddr.isNull()) {{ 
             send({{ type: 'error', payload: 'JS Error: Captured base pointer was null!' }});
            return;
        }} 
        sendStateAddr = cryptoBaseAddr.add(SEND_STATE_OFFSET);
        recvStateAddr = cryptoBaseAddr.add(RECV_STATE_OFFSET);
        send({{ type: 'status', payload: 'Crypto states initialized.' }});
    }} 
}}); 

// --- Hook for Packet Encryption/Decryption ---
Interceptor.attach(arc4EncryptAddr, {{ 
    onEnter: function (args) {{ 
        const statePtr = args[2];
        const dataInPtr = args[0];
        const dataLen = args[1].toInt32();

        this.dataInPtr = dataInPtr; 
        this.dataLen = dataLen;
        this.isSend = false;
        this.isRecv = false;
        this.opcode = 0;
        this.opName = 'UNKNOWN';

        if (sendStateAddr && statePtr.equals(sendStateAddr)) {{ 
            this.isSend = true; 
            if (this.dataInPtr != null && this.dataLen >= 2 && this.dataLen < 0x1000) {{ 
                try {{
                    // C->S: Assume Big Endian, DO byte swap 
                    const littleEndianOpcode = this.dataInPtr.readU16();
                    const bigEndianOpcode = ((littleEndianOpcode & 0xFF) << 8) | ((littleEndianOpcode >> 8) & 0xFF);
                    this.opcode = bigEndianOpcode; 
                    this.opName = cmsgOpcodesDict[bigEndianOpcode.toString()] || `UNKNOWN_CMSG (0x${{bigEndianOpcode.toString(16).toUpperCase().padStart(4, '0')}})`;

                    send({{ 
                        type: 'packet', 
                        direction: 'C->S',
                        opcode: this.opcode,
                        opName: this.opName,
                        length: this.dataLen,
                        dataHex: sendHex(this.dataInPtr, this.dataLen)
                    }}); 
                }} catch (e) {{
                     send({{ type: 'error', payload: 'JS Error logging C->S: ' + e }});
                }}
            }} 

        }} else if (recvStateAddr && statePtr.equals(recvStateAddr)) {{ 
            this.isRecv = true; 
            // S->C processed in onLeave
        }} 
    }}, 
    onLeave: function (retval) {{ 
        if (this.isRecv && this.dataInPtr != null && this.dataLen >= 2) {{ 
            try {{ 
                // S->C: Assume Little Endian, NO byte swap 
                const opcode = this.dataInPtr.readU16(); 
                this.opcode = opcode; 
                this.opName = smsgOpcodesDict[opcode.toString()] || `UNKNOWN_SMSG (0x${{opcode.toString(16).toUpperCase().padStart(4, '0')}})`;

                 send({{ 
                    type: 'packet', 
                    direction: 'S->C',
                    opcode: this.opcode,
                    opName: this.opName,
                    length: this.dataLen,
                    dataHex: sendHex(this.dataInPtr, this.dataLen)
                }}); 

            }} catch (e) {{ 
                 send({{ type: 'error', payload: 'JS Error logging S->C: ' + e }});
            }} 
        }}
        this.isSend = false;
        this.isRecv = false;
    }} 
}}); 


send({{ type: 'status', payload: 'WoW Packet Logger Script Attached.'}});
"""

# --- Frida Worker Thread ---
PACKET_BUFFER_FLUSH_INTERVAL_MS = 150 # Flush packets every 150ms

class FridaWorker(QObject):
    # Signals to communicate with the main GUI thread
    packets_received = pyqtSignal(list) # Emit list of packets
    status_update = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    finished = pyqtSignal()
    attached = pyqtSignal()
    detached = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.session = None
        self.script = None
        self._is_running = False
        self._packet_buffer = []

    def _on_message(self, message, data):
        try:
            if message['type'] == 'error':
                self.error_occurred.emit(f"Frida Error: {message.get('description', 'No description')}\nStack: {message.get('stack', 'No stack trace')}")
            elif message['type'] == 'send':
                payload_data = message['payload']
                if isinstance(payload_data, dict):
                    msg_type = payload_data.get('type')
                    if msg_type == 'packet':
                        self._packet_buffer.append(payload_data) # Buffer packet
                    elif msg_type == 'status':
                        self.status_update.emit(f"[JS Status] {payload_data.get('payload', '')}")
                    elif msg_type == 'error':
                        self.error_occurred.emit(f"[JS Error] {payload_data.get('payload', '')}")
                    elif msg_type == 'log':
                         self.status_update.emit(f"{payload_data.get('payload', '')}")
                    else:
                        self.status_update.emit(f"[JS->Py Other] {payload_data}")
                else:
                    self.status_update.emit(f"[JS->Py Raw] {payload_data}")
            else:
                self.status_update.emit(f"[Frida Message] Type: {message['type']}")
        except Exception as e:
            self.error_occurred.emit(f"Python Error processing message: {e}")

    @pyqtSlot()
    def _flush_packet_buffer(self):
        if self._packet_buffer:
            buffer_copy = self._packet_buffer[:]
            self._packet_buffer.clear()
            self.packets_received.emit(buffer_copy)

    @pyqtSlot()
    def run(self):
        self._is_running = True
        self._packet_buffer = []
        
        flush_timer = QTimer() 
        flush_timer.timeout.connect(self._flush_packet_buffer)
        flush_timer.start(PACKET_BUFFER_FLUSH_INTERVAL_MS)
        
        try:
            self.status_update.emit("Attaching...")
            self.session = frida.attach(PROCESS_NAME)
            self.status_update.emit("Attached. Loading script...")
            def on_detached():
                if self._is_running:
                     self.error_occurred.emit("Frida session detached unexpectedly!")
                     self.stop()
            self.session.on('detached', on_detached)
            self.script = self.session.create_script(javascript_code)
            self.script.on('message', self._on_message)
            self.script.load()
            self.status_update.emit("Script loaded. Sending opcodes...")
            smsg_opcodes_str_keys = {str(k): v for k, v in smsg_opcodes.items()}
            cmsg_opcodes_str_keys = {str(k): v for k, v in cmsg_opcodes.items()}
            self.script.post({
                'type': 'opcodes',
                'payload': {
                    'smsg': smsg_opcodes_str_keys,
                    'cmsg': cmsg_opcodes_str_keys
                }
            })
            self.status_update.emit("Opcodes sent.")
            self.attached.emit() 

            loop = QEventLoop()
            while self._is_running:
                 loop.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)

        except Exception as e:
            self.error_occurred.emit(f"Error in Frida thread: {e}") 
        finally:
            flush_timer.stop()
            self.cleanup()
            self.finished.emit()

    @pyqtSlot()
    def stop(self):
        if not self._is_running:
            return
        self.status_update.emit("Stop requested. Detaching...")
        self._is_running = False 
        self.cleanup()

    def cleanup(self):
        if self.script: 
            try: self.script.unload() 
            except Exception as e: print(f"Error unloading script: {e}")
            self.script = None
        if self.session:
             try: 
                 if self.session.is_attached:
                     self.session.detach()
             except Exception as e: print(f"Error detaching session: {e}")
             self.session = None
        print("FridaWorker cleanup performed.")

# --- Main Application Window --- 
MAX_PACKET_HISTORY = 5000 # Limit number of packets stored

class PacketViewerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WoW 3.3.5 Packet Viewer")
        self.setGeometry(100, 100, 1000, 700) 
        self.frida_thread = None
        self.frida_worker = None

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        controls_layout = QHBoxLayout()
        self.attach_button = QPushButton("Attach to Wow.exe")
        self.detach_button = QPushButton("Detach")
        self.detach_button.setEnabled(False)
        self.status_label = QLabel("Status: Detached")
        
        filter_label = QLabel("Filter Opcode (Name/Hex/Dec):") # Updated label
        self.filter_input = QLineEdit()
        controls_layout.addWidget(self.attach_button)
        controls_layout.addWidget(self.detach_button)
        controls_layout.addStretch(1)
        controls_layout.addWidget(filter_label)
        controls_layout.addWidget(self.filter_input)
        controls_layout.addStretch(1)
        controls_layout.addWidget(self.status_label)
        main_layout.addLayout(controls_layout)

        self.packet_display = QTextEdit()
        self.packet_display.setReadOnly(True)
        self.packet_display.setFontFamily("Consolas") 
        main_layout.addWidget(self.packet_display)

        self.attach_button.clicked.connect(self.start_frida)
        self.detach_button.clicked.connect(self.stop_frida)
        self.filter_input.textChanged.connect(self.apply_filter)
        self.current_filter = ""
        # Use deque for limited history
        self.all_packets = deque(maxlen=MAX_PACKET_HISTORY)

    @pyqtSlot()
    def start_frida(self):
        if self.frida_thread is not None:
            self.append_log("Already attached or attempting attach.")
            return
            
        self.packet_display.clear()
        self.all_packets.clear() # Clear deque
        self.append_log("Starting Frida thread...")
        self.status_label.setText("Status: Initializing...")
        self.attach_button.setEnabled(False)

        self.frida_thread = QThread()
        self.frida_worker = FridaWorker()
        self.frida_worker.moveToThread(self.frida_thread)

        self.frida_worker.packets_received.connect(self.handle_packets_batch)
        self.frida_worker.status_update.connect(self.update_status)
        self.frida_worker.error_occurred.connect(self.handle_error)
        self.frida_worker.attached.connect(self.on_frida_attached)
        self.frida_worker.detached.connect(self.on_frida_detached)
        self.frida_worker.finished.connect(self.on_worker_finished)
        
        self.frida_thread.started.connect(self.frida_worker.run)
        self.frida_thread.finished.connect(self.on_thread_finished)
        self.frida_thread.start()

    @pyqtSlot()
    def stop_frida(self):
        self.update_status("Detaching requested...")
        if self.frida_worker:
            self.frida_worker.stop()
        if self.frida_thread:
            self.frida_thread.quit()
            if not self.frida_thread.wait(3000):
                 self.append_log("Warning: Frida thread did not exit cleanly.")
            else:
                 self.append_log("Frida thread finished.")

    @pyqtSlot()
    def on_worker_finished(self):
        self.append_log("FridaWorker finished signal received.")
        if self.frida_thread: 
             self.frida_thread.quit()
        self.frida_worker = None 
        if not self.frida_thread:
             self.on_frida_detached()

    @pyqtSlot()
    def on_thread_finished(self):
        self.append_log("Frida QThread finished signal received.")
        self.frida_thread = None
        if not self.frida_worker:
             self.on_frida_detached()

    @pyqtSlot()
    def on_frida_attached(self):
        self.update_status("Attached & Running")
        self.detach_button.setEnabled(True)

    @pyqtSlot()
    def on_frida_detached(self):
        if self.status_label.text() != "Status: Detached":
            self.update_status("Detached")
            self.attach_button.setEnabled(True)
            self.detach_button.setEnabled(False)
            self.frida_thread = None 
            self.frida_worker = None
        print("Detached UI update complete")
        
    @pyqtSlot(list) 
    def handle_packets_batch(self, packet_batch):
        scrollbar = self.packet_display.verticalScrollBar()
        scroll_at_bottom = scrollbar.value() >= (scrollbar.maximum() - 15) 
        for packet_data in packet_batch:
            self.all_packets.append(packet_data) 
            if self._packet_matches_filter(packet_data, self.current_filter):
                line = self._format_packet_line(packet_data)
                self.packet_display.append(line) 
        if scroll_at_bottom:
             scrollbar.setValue(scrollbar.maximum())

    @pyqtSlot(str)
    def update_status(self, message):
        self.status_label.setText(f"Status: {message}")
        self.append_log(message)

    @pyqtSlot(str)
    def handle_error(self, error_message):
        self.status_label.setText("Status: Error")
        self.append_log(f"ERROR: {error_message}")
        
    def append_log(self, text):
        scrollbar = self.packet_display.verticalScrollBar()
        scroll_at_bottom = scrollbar.value() >= (scrollbar.maximum() - 15) 
        self.packet_display.append(text)
        if scroll_at_bottom:
             scrollbar.setValue(scrollbar.maximum())

    @pyqtSlot()
    def apply_filter(self):
        self.current_filter = self.filter_input.text().strip().lower()
        self.packet_display.clear() 
        for packet_data in self.all_packets: 
             if self._packet_matches_filter(packet_data, self.current_filter):
                 line = self._format_packet_line(packet_data)
                 self.packet_display.append(line)
        self.packet_display.verticalScrollBar().setValue(self.packet_display.verticalScrollBar().maximum())

    def _packet_matches_filter(self, packet_data, filter_text):
        if not filter_text:
            return True 
        op_hex = f"0x{packet_data.get('opcode', 0):04X}"
        op_name = packet_data.get('opName', '').lower()
        op_dec = str(packet_data.get('opcode', -1))
        if filter_text in op_hex.lower() or \
           filter_text == op_dec or \
           filter_text in op_name:
            return True
        return False
        
    def _format_packet_line(self, packet_data):
         op_hex = f"0x{packet_data.get('opcode', 0):04X}"
         return f"[{packet_data.get('direction')}] Op: {packet_data.get('opName')} ({op_hex}) Len: {packet_data.get('length')} Data: {packet_data.get('dataHex', '')[:64]}..."

    def closeEvent(self, event):
        self.stop_frida()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketViewerWindow()
    window.show()
    sys.exit(app.exec())
