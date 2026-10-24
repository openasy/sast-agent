import java.beans.XMLDecoder;
import java.io.InputStream;
import java.io.ObjectInputStream;

class Read {
    Object read(InputStream body) throws Exception {
        ObjectInputStream in = new ObjectInputStream(body);
        // ruleid: openasy.java.unsafe-deserialization
        Object o = in.readObject();
        // ruleid: openasy.java.unsafe-deserialization
        XMLDecoder d = new XMLDecoder(body);
        // ok: openasy.java.unsafe-deserialization
        int n = body.read();
        return o;
    }
}
