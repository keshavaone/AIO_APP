from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import sys, os, time, ast, logging, hashlib, base64
import pandas as pd
from cryptography.fernet import Fernet
from SecureAPI import Agent  # type: ignore
import CONSTANTS  #type: ignore

# Setup logging with rotation
from logging.handlers import RotatingFileHandler
from PyQt5.QtWidgets import QLineEdit
handler = RotatingFileHandler('application.log', maxBytes=1000000, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO)

class PIIWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('PII')
        self.setGeometry(100, 100, 1000, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8fbd9;
            }
            QPushButton {
                background-color: #4CAF50; 
                color: white; 
                font-size: 16px; 
                padding: 10px;
                border-radius: 5px;
            }
        """)
        self.UIComponents()
        self.show()
        self.showMaximized()

        # Connect the close event to the cleanup function
        self.closeEvent = self.cleanup_on_exit

    def UIComponents(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        welcome_text = QLabel(f"Welcome to PII Application: {os.getlogin()}", central_widget)
        welcome_text.setStyleSheet("font-size: 15px; font-weight: bold;")
        layout.addWidget(welcome_text, alignment=Qt.AlignCenter)

        self.btnConnectServer = QPushButton('Connect to Server', self)
        self.btnConnectServer.setToolTip('Click to connect to the server')
        self.btnConnectServer.setCursor(QCursor(Qt.PointingHandCursor))
        self.btnConnectServer.setIcon(QIcon('connect.png'))
        self.btnConnectServer.setShortcut('Ctrl+Q')
        self.btnConnectServer.clicked.connect(self.show_password_input)
        layout.addWidget(self.btnConnectServer, alignment=Qt.AlignCenter)

        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.authenticate_and_connect)
        self.password_input.setHidden(True)
        layout.addWidget(self.password_input)

        self.data_table = QTableWidget(self)
        self.data_table.setColumnCount(1)
        self.data_table.setHorizontalHeaderLabels(['Item Name'])
        self.data_table.horizontalHeader().setStretchLastSection(True)
        self.data_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.data_table.itemSelectionChanged.connect(self.on_data_table_selection)
        self.data_table.setAlternatingRowColors(True)
        layout.addWidget(self.data_table)

        self.log_table = QTableWidget(self)
        self.log_table.setColumnCount(2)
        self.log_table.setHorizontalHeaderLabels(['Timestamp', 'Action/Task Performed'])
        self.log_table.horizontalHeader().setStretchLastSection(True)
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.log_table.setAlternatingRowColors(True)
        layout.addWidget(self.log_table)

        self.btnDisplayData = QPushButton('Display Data', self)
        self.btnDisplayData.setDisabled(True)
        self.btnDisplayData.setToolTip('Button Disabled. Please Connect to Server')
        self.btnDisplayData.setCursor(QCursor(Qt.PointingHandCursor))
        self.btnDisplayData.setIcon(QIcon('download.png'))
        self.btnDisplayData.setShortcut('Ctrl+S')
        self.btnDisplayData.setStyleSheet("background-color: gray; color: black;")
        self.btnDisplayData.clicked.connect(self.show_data_window)
        layout.addWidget(self.btnDisplayData, alignment=Qt.AlignCenter)

    # def upload_pii(self):
    #     try:
    #         if os.path.exists('MyPII.PIIData.xlsx'):
    #             pre_upload_time_stamp = time.time()
    #             self.update_log(self.agent.get_current_time(), "PII Data Upload Attempted.")
                
    #             # Encrypt the file before uploading
    #             try:
    #                 encrypted_file_path = self.encrypt_file('MyPII.PIIData.xlsx')
    #             except Exception as e:
    #                 error_message = f"Error encrypting file: {str(e)}"
    #                 self.update_log(self.agent.get_current_time(), error_message)
    #                 QMessageBox.critical(self, "Encryption Error", error_message)
    #                 return
                
    #             # Attempt to upload the encrypted file
    #             try:
    #                 response = self.agent.upload_excel_to_s3(encrypted_file_path)
    #             except Exception as e:
    #                 error_message = f"Error uploading file: {str(e)}"
    #                 self.update_log(self.agent.get_current_time(), error_message)
    #                 QMessageBox.critical(self, "Upload Error", error_message)
    #                 return
                
    #             self.update_log(self.agent.get_current_time(), "PII Data Upload Function Response: " + str(response))
    #             self.update_log(self.agent.get_current_time(), f"PII Data Upload Time: {time.time() - pre_upload_time_stamp:.2f} Seconds")
                
    #             if response:
    #                 QMessageBox.information(self, "Upload Complete", "Data uploaded successfully!")
    #             else:
    #                 QMessageBox.warning(self, "Upload Failed", "Failed to upload data!")
    #         else:
    #             QMessageBox.warning(self, "File Not Found", "File 'MyPII.PIIData.xlsx' not found!")
    #             self.update_log(self.agent.get_current_time(), "File 'MyPII.PIIData.xlsx' not found!")
    #     except Exception as e:
    #         error_message = f"Unexpected error: {str(e)}"
    #         self.update_log(self.agent.get_current_time(), error_message)
    #         QMessageBox.critical(self, "Error", error_message)
    

    def download_pii(self):
        self.update_log(self.agent.get_current_time(), "PII Data Download Attempted")
        pre_download_time_stamp = time.time()
        response = self.agent.download_excel()
        self.update_log(self.agent.get_current_time(), f"PII Data Download Time: {time.time() - pre_download_time_stamp:.2f} Seconds")
        self.update_log(self.agent.get_current_time(), "PII Data Download Function Response: " + str(response))
        if response:
            QMessageBox.information(self, "Download Complete", "Data downloaded and decrypted successfully!")
        else:
            QMessageBox.warning(self, "Download Failed", "Failed to download data!")

    def show_password_input(self):
        self.btnConnectServer.setText('Connecting...')
        self.btnConnectServer.setDisabled(True)
        self.btnConnectServer.setStyleSheet("background-color: gray; color: white;")
        self.password_input.setHidden(False)  # Make the password input visible
        self.password_input.setFocus()
        self.btnConnectServer.clicked.disconnect(self.show_password_input)
        self.btnConnectServer.clicked.connect(self.authenticate_and_connect)

    
    def show_data_window(self):
        # Secure the window by disabling certain features
        data_window = QMainWindow(self)
        data_window.setWindowTitle("PII Data")
        data_window.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowTitleHint | Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint)
    
        central_widget = QWidget(data_window)
        data_window.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
    
        self.table_widget = QTableWidget()
        layout.addWidget(self.table_widget)
    
        data_frame = self.agent.get_all_data()
        self.data_frame = data_frame.copy()  # Store data frame locally for later use
        self.update_log(self.agent.get_current_time(), 'PII Data Displaying...')
    
        # Set DataFrame data to QTableWidget
        if isinstance(data_frame, pd.DataFrame):
            num_rows, num_columns = data_frame.shape
            self.table_widget.setRowCount(num_rows)
            self.table_widget.setColumnCount(num_columns)
            self.table_widget.setHorizontalHeaderLabels(data_frame.columns.tolist())
            self.table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
    
            for row in range(num_rows):
                for col in range(num_columns):
                    value = data_frame.iat[row, col]
                    
                    # Check if the column is 'PII' and contains a list of dictionaries
                    if data_frame.columns[col] == 'PII' and isinstance(value, str):
                        try:
                            pii_list = ast.literal_eval(value)
                            if isinstance(pii_list, list) and all(isinstance(d, dict) for d in pii_list):
                                formatted_value = '\n'.join(
                                    f"{d['Item Name']} - {str(d['Data'])}"
                                    for d in pii_list if 'Item Name' in d and 'Data' in d
                                )
                                item = QTableWidgetItem(formatted_value)
                            else:
                                item = QTableWidgetItem(str(value))
                        except (ValueError, SyntaxError):
                            item = QTableWidgetItem(str(value))
                    else:
                        item = QTableWidgetItem(str(value))
                    
                    self.table_widget.setItem(row, col, item)
    
            # Add context menu actions
            self.table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table_widget.customContextMenuRequested.connect(self.open_context_menu)
    
        btnDownload = QPushButton('Download Data', data_window)
        btnDownload.setCursor(QCursor(Qt.PointingHandCursor))
        btnDownload.setIcon(QIcon('download.png'))
        btnDownload.clicked.connect(self.download_pii)
        layout.addWidget(btnDownload)
    
        # btnUpload = QPushButton('Upload Data', data_window)
        # btnUpload.setCursor(QCursor(Qt.PointingHandCursor))
        # btnUpload.setIcon(QIcon('upload.png'))
        # btnUpload.clicked.connect(self.upload_pii)
        # layout.addWidget(btnUpload)
    
        self.table_widget.resizeColumnsToContents()
        self.table_widget.resizeRowsToContents()
        self.table_widget.setSortingEnabled(True) 
        self.table_widget.sortByColumn(0, Qt.AscendingOrder)
        self.table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_widget.horizontalHeader().setStretchLastSection(True)
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_widget.verticalHeader().setVisible(False)
        self.table_widget.setAlternatingRowColors(True)
        self.table_widget.setStyleSheet("QTableWidget::item { padding: 5px; }")
    
        self.pii_table_strt_time = time.time()
        data_window.showMaximized()
        data_window.show()
    
        def on_close_event(event):
            event.accept()
            self.update_log(self.agent.get_current_time(), f'Application PII Window Closed')
            close_event_strt_time = time.time()
            self.agent.upload_securely()

            self.update_log(self.agent.get_current_time(), f'Data Backed Up in {time.time() - close_event_strt_time:.2f} Seconds')
            self.update_log(self.agent.get_current_time(), f'Application PII Window Closed after {time.time() - close_event_strt_time:.2f} Seconds')
            
            

        data_window.closeEvent = on_close_event
    
    def open_context_menu(self, position):
        menu = QMenu()
    
        copy_action = QAction('Copy', self)
        copy_action.triggered.connect(self.copy_selected_row)
        menu.addAction(copy_action)

        edit_action = QAction('Edit', self)
        edit_action.triggered.connect(self.edit_selected_row)
        menu.addAction(edit_action)

        menu.exec_(self.table_widget.viewport().mapToGlobal(position))
    
    def edit_selected_row(self):
        selected_items = self.table_widget.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[2].row()
        column = selected_items[2].column()
        item = self.table_widget.item(row, column)
        
        if item is None:
            return
    
        old_value = item.text()
    
        # Create and set up the dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit PII")
        layout = QVBoxLayout()
        text_edit = QTextEdit()
        text_edit.setPlainText(old_value)
        layout.addWidget(text_edit)
    
        # Add OK and Cancel buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
    
        # Connect buttons to appropriate slots
        ok_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
    
        # Show the dialog and handle the result
        if dialog.exec_() == QDialog.Accepted:
            new_value = text_edit.toPlainText()
            item.setText(new_value)
            try:
                list_of_lists = [i.split(' - ') for i in new_value.split('\n')]
                # print(list_of_lists)
                new_value1 = ""
                for i in list_of_lists:
                    item_name = i[0]
                    data = i[1]
                    new_value1 += '{"Item Name": "'+item_name+'", "Data":"'+data+'"},'
                final_value = "["+new_value1[:-1]+"]"
            except:
                final_value = new_value
            final_item = {}

            row = selected_items[0].row()
            column = selected_items[0].column()
            final_item["Category"] = self.table_widget.item(row, column).text()

            row = selected_items[1].row()
            column = selected_items[1].column()
            final_item["Type"] = self.table_widget.item(row, column).text()
            
            final_item["PII"] = final_value
            print(final_item)
            self.time_updt_strt_time = time.time()
            modified_count, response = self.agent.update_one_data(final_item)
            self.update_log(self.agent.get_current_time(), f"Modified {modified_count} document(s)")
            self.update_log(self.agent.get_current_time(), f"Update Time: {time.time() - self.time_updt_strt_time:.2f} Seconds")
            self.update_log(self.agent.get_current_time(), f"Update Function Response: {response}")
            self.update_log(self.agent.get_current_time(), f"Modifed: {final_item['Category']}'s {final_item['Type']} - PII")
            QMessageBox.information(self, "Update Complete", f"{modified_count} document(s) updated successfully!")
    
        


    def copy_selected_row(self):
        selected_items = self.table_widget.selectedItems()
        if selected_items:
            clipboard = QApplication.clipboard()
            clipboard.setText('\t'.join([item.text() for item in selected_items]))

    def authenticate_and_connect(self):
        password = self.password_input.text()
        env_password = CONSTANTS.APP_PASSWORD

        if not env_password:
            QMessageBox.warning(self, "Security Warning", "Please Activate your Secure Environment before performing operations")
            return 

        hashed_input_password = hashlib.sha256(password.encode()).hexdigest()
        hashed_env_password = hashlib.sha256(env_password.encode()).hexdigest()

        if hashed_input_password == hashed_env_password:
            self.btnConnectServer.setStyleSheet("background-color: orange; color: white;")
            self.password_input.clear()
            self.password_input.setHidden(True)
            self.connect_to_server()
            self.update_log(self.agent.get_current_time(), 'Authentication Successful')
        else:
            QMessageBox.warning(self, "Authentication Failed", "Incorrect Password!")
            self.password_input.clear()

    
    
    def connect_to_server(self):
        self.btnConnectServer.setDisabled(True)
        self.agent = Agent(s3=CONSTANTS.AWS_S3, file_name=CONSTANTS.AWS_FILE)
        self.btnConnectServer.setText('Connected')
        self.btnConnectServer.setDisabled(True)
        self.btnConnectServer.setStyleSheet("background-color: green; color: white;")
        self.btnDisplayData.setStyleSheet("background-color: green; color: white;")
        self.btnDisplayData.setDisabled(False)
        self.btnDisplayData.setToolTip('Click to download data')
        self.btnConnectServer.setToolTip('You are Connected Successfully. Button Disabled')

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.fetch_status)
        self.timer.start(1000)
        data = self.agent.get_options_to_choose()
        self.populate_data_table(data)
        self.update_log(self.agent.get_current_time(), "Connected to Server.")
        self.update_log(self.agent.get_current_time(), 'Display Data Button: Activated')

    def on_data_table_selection(self):
        selected_items = self.data_table.selectedItems()
        if not selected_items:
            return
        selected_item_text = selected_items[0].text()
        sub_options = self.agent.get_sub_options_to_choose(selected_item_text)
        self.update_log(self.agent.get_current_time(), f"Selected item: {selected_item_text}")

        sub_option, ok_pressed = QInputDialog.getItem(
            self,
            "Choose Sub Option",
            f"Sub options for {selected_item_text}:",
            sub_options,
            0,
            False
        )
        if ok_pressed and sub_option:
            output = self.agent.get_final_output(sub_option)
            self.update_log(self.agent.get_current_time(), f"Selected {selected_item_text}'s sub option: {sub_option}")
            self.show_output_dialog(sub_option, output)

    def show_output_dialog(self, sub_option, output):
        self.start_time = time.time()

        def on_close_event(event):
            event.accept()
            end_time = time.time() - self.start_time
            self.update_log(self.agent.get_current_time(), f"{self.option}'s dialog closed after {end_time:.2f} seconds")
            

        dialog = QDialog(self)
        dialog.setWindowTitle(sub_option)
        dialog.setGeometry(200, 200, 500, 400)
        dialog.resize(700, 300)
        self.option = sub_option
        dialog.move(QCursor.pos())

        dialog_layout = QVBoxLayout(dialog)
        dialog.closeEvent = on_close_event
        scroll_area = QScrollArea(dialog)
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_content.maximumSize()
        dialog.maximumSize()
        for item in output:
            h_layout = QHBoxLayout()
            copy_button = QPushButton('Copy', dialog)
            copy_button.setToolTip('Click to copy the data')
            copy_button.setCursor(QCursor(Qt.PointingHandCursor))
            if isinstance(item, dict):
                label = QLabel(f"{item['Item Name']} : {str(item['Data'])}", dialog)
                copy_button.clicked.connect(lambda checked, data=item: self.copy_to_clipboard(data))
                label.setWordWrap(True)
                label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
                h_layout.addWidget(label)
                h_layout.addWidget(copy_button)
                scroll_layout.addLayout(h_layout)
                scroll_layout.addSpacing(10)
            else:
                QMessageBox.warning(self, "Error Code: 404 and 503 WARNING MESSAGE", "You are Not Allowed to view this here.")
                return
        self.update_log(self.agent.get_current_time(), f"Displaying... {self.option}")

        scroll_content.setLayout(scroll_layout)
        scroll_area.setWidget(scroll_content)

        dialog_layout.addWidget(scroll_area)
        dialog_layout.maximumSize()
        close_button = QPushButton('Close', dialog)
        dialog_layout.addWidget(close_button)
        dialog_layout.setAlignment(close_button, Qt.AlignRight)

        # Record the start time
        start_time = time.time()

        # Function to handle dialog acceptance
        def on_accept():
            end_time = time.time()
            duration = end_time - start_time
            self.update_log(self.agent.get_current_time(), f"{self.option}'s dialog was visible for {duration:.2f} seconds")
            dialog.accept()

        close_button.clicked.connect(on_accept)

        dialog.exec_()

    def fetch_status(self):
        if hasattr(self, 'agent') and hasattr(self.agent, 'status'):
            for task_name, task_time in self.agent.status.items():
                self.update_log(task_time, task_name)
            self.agent.status = {}

    def copy_to_clipboard(self, data):
        clipboard = QApplication.clipboard()
        clipboard.setText(str(data['Data']))
        
        self.update_log(self.agent.get_current_time(), f"Copied {self.option}'s {data['Item Name']} to Clipboard.")
        QMessageBox.information(self, "Copied", f"{data['Item Name']} Copied to Clipboard.")

    def update_log(self, task_time, task_name):
        row_position = self.log_table.rowCount()
        self.log_table.insertRow(row_position)

        timestamp_item = QTableWidgetItem(task_time)
        message_item = QTableWidgetItem(task_name)

        self.log_table.setItem(row_position, 0, timestamp_item)
        self.log_table.setItem(row_position, 1, message_item)

        logging.info(f"{task_time} - {task_name}")

    def populate_data_table(self, data):
        self.data_table.setRowCount(len(data))
        for row, item in enumerate(data):
            self.data_table.setItem(row, 0, QTableWidgetItem(item))

    def encrypt_file(self, file_path):
        key = os.environ.get('ENCRYPTION_KEY')
        if not key:
            key = base64.urlsafe_b64encode(hashlib.sha256(os.urandom(32)).digest())
            os.environ['ENCRYPTION_KEY'] = key.decode()
        cipher_suite = Fernet(key)
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_data)
        return encrypted_file_path

    def decrypt_file(self, encrypted_file_path):
        key = os.environ.get('ENCRYPTION_KEY')
        if not key:
            raise ValueError("Encryption key not found in environment variables.")
        cipher_suite = Fernet(key)
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        decrypted_file_path = encrypted_file_path.replace('.enc', '')
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)
        return decrypted_file_path

    def cleanup_on_exit(self, event):
       log_files = ['application.log']
       print('Performing Clean Up')
       for log_file in log_files:
        if os.path.exists(log_file):
            logging.info("Cleanup completed successfully.")
            self.agent.collect_logs()

        # Delete encrypted files
        # encrypted_files = [file for file in os.listdir('.') if file.endswith('.enc')]
        # for enc_file in encrypted_files:
        #     os.remove(enc_file)
        # return True
        # Optional: You can delete any other temporary files created by your application here.
            
        # except Exception as e:
        #     logging.error(f"Error during cleanup: {str(e)}")
        #     # return False
        # finally:
        #     event.accept()
            # return True
    
    def update_item(self, item):
        self.data_table.setCurrentItem(item, QAbstractItemView.Select)
        self.on_data_table_selection()
        self.data_table.setCurrentItem(None)
        self.data_table.clearSelection()
        self.data_table.update()
        self.data_table.repaint()
        self.data_table.viewport().update()
        self.data_table.viewport().repaint()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PIIWindow()
    sys.exit(app.exec_())