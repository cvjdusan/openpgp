package etf.openpgp.cd170169d;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.FileHandler;

public class KeyTableModel extends AbstractTableModel {

    private final List<String> summaries;

    String[] columnNames  = new String[] { "Ime", "Email", "keyID" };

    public KeyTableModel() {
        this.summaries = new ArrayList<String>();
        this.summaries.add("Test");
        this.summaries.add("Test2");
    }
    // Other TabelModel methods...

    public void refresh() {
        //summaries = new ArrayList<>(FileHandler.getCompletedPlayers());
        summaries.add("Test3");
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return summaries.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }


    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        String personObj = summaries.get(rowIndex);

        switch(columnIndex){
            case 0: return personObj;
            case 1: return personObj;
            case 2: return personObj;
            case 3: return personObj;
            default : return null;
        }
    }
}
