package etf.openpgp.cd170169d;

import org.bouncycastle.openpgp.PGPPublicKeyRing;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

public class KeyTableModel extends AbstractTableModel {

    private List<Key> keys;

    String[] columnNames  = new String[] { "Ime", "Email", "keyID" };

    public KeyTableModel() {
        this.keys = new ArrayList<Key>();
    }

    public void refresh() {
        //summaries = new ArrayList<>(FileHandler.getCompletedPlayers());
        fireTableDataChanged();
    }

    public void add(Key k){
        this.keys.add(k);
        refresh();
    }

    public void clearList(){
        this.keys.clear();
    }

    @Override
    public int getRowCount() {
        return keys.size();
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
        Key key = keys.get(rowIndex);

        switch(columnIndex){
            case 0:
                return key.getName();
            case 1:
                return key.getEmail();
            case 2:
                return key.getId();
            default :
                return null;
        }
    }
    
    public Long getKeyLongId(String id){
        Long value = null;
        
        for(int i = 0; i < keys.size(); i++){
            if(keys.get(i).getId().equals(id)) {
                value = keys.get(i).getLongKeyId();
                break;
            }
        }
        
        return value;
    }

    public void deleteKey(String id1) {
        keys.removeIf( id -> id.equals(id1));
    }

    public ArrayList<String> getKeysString() {
        ArrayList<String> s = new ArrayList<>();

        keys.forEach(k -> {
            s.add(k.getName() + " " + k.getEmail() + " " + k.getId());
        });

        return s;
    }
}
