package etf.openpgp.cd170169d;

import org.bouncycastle.openpgp.PGPPublicKeyRing;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Pomocna klasa koja upravlja prikazom tabele kljuceva
 *
 */
public class KeyTableModel extends AbstractTableModel {

    private List<Key> keys;

    String[] columnNames  = new String[] { "Ime", "Email", "keyID" };

    public KeyTableModel() {
        this.keys = new ArrayList<Key>();
    }

    /**
     * Osvezavanje podataka u tabeli
     */

    public void refresh() {
        //summaries = new ArrayList<>(FileHandler.getCompletedPlayers());
        fireTableDataChanged();
    }

    /**
     * Dodavanje kljuca u tabelu
     * @param k
     */

    public void add(Key k){
        this.keys.add(k);
        refresh();
    }

    /**
     * Brisanje svih kljuceva u tabeli
     */

    public void clearList(){
        this.keys.clear();
    }

    /**
     * Vraca broj redova u tabeli
     * @return int
     */

    @Override
    public int getRowCount() {
        return keys.size();
    }

    /**
     * Vraca broj kolona u tabeli
     * @return int
     */

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    /**
     * Vraca ime kolone
     *
     * @param column
     * @return
     */

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    /**
     * Vraca objetak u redu i koloni
     *
     * @param rowIndex
     * @param columnIndex
     * @return
     */

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

    /**
     * Vraca Long vrednost kljuca
     *
     * @param id
     * @return
     */

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

    /**
     * Brise kljuc iz reda
     *
     * @param id1
     */

    public void deleteKey(String id1) {
        keys.removeIf( id -> id.equals(id1));
    }

    /**
     * Vraca opis kljuca
     *
     * @return
     */

    public ArrayList<String> getKeysString() {
        ArrayList<String> s = new ArrayList<>();

        keys.forEach(k -> {
            s.add(k.getName() + " " + k.getEmail() + " " + k.getId());
        });

        return s;
    }
}
