import com.google.ctf.food.ℝ;

/* original F.cc()
class F {
    ...

    public void cc() {
        byte[] bArr = new byte[]{(byte) 26, (byte) 27, (byte) 30, (byte) 4, (byte) 21, (byte) 2, (byte) 18, (byte) 7};
        for (int i = 0; i < 8; i++) {
            bArr[i] = (byte) (bArr[i] ^ this.k[i]);
        }
        if (new String(bArr).compareTo("\u0013\u0011\u0013\u0003\u0004\u0003\u0001\u0005") == 0) {
            Toast.makeText(this.a.getApplicationContext(), new String(R.C(flag, this.k)), 1).show();
        }
    }
}
*/

// call modified F.cc() to output the flag
public class Solve {

    // unmodified from class F
    private static byte[] flag = new byte[]{(byte) -19, (byte) 116, (byte) 58, (byte) 108, (byte) -1, (byte) 33, (byte) 9, (byte) 61, (byte) -61, (byte) -37, (byte) 108, (byte) -123, (byte) 3, (byte) 35, (byte) 97, (byte) -10, (byte) -15, (byte) 15, (byte) -85, (byte) -66, (byte) -31, (byte) -65, (byte) 17, (byte) 79, (byte) 31, (byte) 25, (byte) -39, (byte) 95, (byte) 93, (byte) 1, (byte) -110, (byte) -103, (byte) -118, (byte) -38, (byte) -57, (byte) -58, (byte) -51, (byte) -79};

    // simply calculate k from the expected result (compareTo)
    // modified from F.cc()
    public static byte[] cc() {
	byte[] k = new byte[8];
        byte[] bArr = new byte[]{(byte) 26, (byte) 27, (byte) 30, (byte) 4, (byte) 21, (byte) 2, (byte) 18, (byte) 7};
	byte[] compareTo = new byte[]{(byte) 0x13, (byte) 0x11, (byte) 0x13, (byte) 0x3, (byte) 0x4, (byte) 0x3, (byte) 0x1, (byte) 0x5};
        for (int i = 0; i < 8; i++) {
            k[i] = (byte) (bArr[i] ^ compareTo[i]);
	    System.out.format("%d ", k[i]);  // output food ids as well
        }
	System.out.println();
	return ℝ.ℂ(flag, k);
    }
    
    public static void main(String[] args) {
        System.out.println(new String(cc()));
    }
}
