from PyQt5.QtWidgets import QMessageBox
import handler as handler


class MessageBoxes:

    def infobox(self, message):
        QMessageBox.information(self, 'Info', message, QMessageBox.Ok)

    def warningbox(self, message):
        QMessageBox.warning(self, 'Warning', message, QMessageBox.Close)

    def criticalbox(self, message):
        QMessageBox.critical(self, 'Error', message, QMessageBox.Close)

    def question(self, message):
        QMessageBox.question(self, 'Question', message, QMessageBox.Ok)

    def noicon(self, message):
        QMessageBox.noicon(self, '', message, QMessageBox.Ok)

    def infobox_update(self, message):
        title = f'Windows Deployment Tool v{handler.handler.wdt_current_version()}'
        button_reply = QMessageBox.information(self, title, message, QMessageBox.Yes, QMessageBox.No)
        if button_reply == QMessageBox.Yes:
            handler.open_releases_website()



