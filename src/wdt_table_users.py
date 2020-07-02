from PyQt5.QtWidgets import QTableWidgetItem


class BaseTable:
    def __init__(self, table):
        self.table = table

    def set_item(self, i: int, j: int, item: str) -> None:
        self.table.setItem(i, j, QTableWidgetItem(item))

    def get_item(self, i: int, j: int) -> str:
        result = self.table.item(i, j)
        if result != None:
            return result.text()
        return ""

    def add_row(self):
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)

    def get_shape(self):
        """Returns (row_count, column_count)"""
        return (self.get_rows(), self.get_columns())

    def get_rows(self) -> int:
        return self.table.rowCount()

    def get_columns(self) -> int:
        return self.table.columnCount()

    def clearContents(self):
        self.table.clearContents()