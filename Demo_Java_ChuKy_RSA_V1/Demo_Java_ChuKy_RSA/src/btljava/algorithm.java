package btljava;

import java.math.BigInteger;
import java.util.Random;

public class algorithm extends SHA1 {
    private BigInteger p, q, n, d, e;

    public algorithm() {

    }

    public algorithm(BigInteger p, BigInteger q) {
        this.p = p;
        this.q = q;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getQ() {
        return q;
    }

    public void setQ(BigInteger q) {
        this.q = q;
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    public BigInteger getE() {
        return e;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

    //Hàm kiểm tra số nguyên tố
    public boolean isPrime(BigInteger x) {
        if (x.compareTo(BigInteger.valueOf(2)) < 0)
            return false;
        if (x.equals(BigInteger.valueOf(2)))
            return true;
        if (x.compareTo(BigInteger.valueOf(2)) > 0) {
            if (x.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO))
                return false;
            else {
                for (BigInteger i = BigInteger.valueOf(3); i.compareTo(x.sqrt()) <= 0; i = i.add(BigInteger.valueOf(1))) {
                    if (x.mod(i).equals(BigInteger.ZERO))
                        return false;
                }
            }
        }
        return true;
    }

    //Hàm tính modular multiplicative inverse của a modulo b sử dụng thuật toán Euclidean.
    BigInteger mul_inv(BigInteger a, BigInteger b) {
        BigInteger b0 = b, t, q;
        BigInteger x0 = BigInteger.ZERO, x1 = BigInteger.ONE;
        if (b.equals(BigInteger.ONE)) return BigInteger.ONE; //Kiểm tra nếu modulo b băng 1 thì trả về 1 luôn đây là mặc định, vì số nào chia lấy dư cho 1 vẫn bằng 0
        while (a.compareTo(BigInteger.ZERO) < 0) a = a.add(b); //Kiểm tra nếu a là số âm thì cộng thêm b để khi a modulo với b ko bị thay đổi giá trị
        while (a.compareTo(BigInteger.ONE) > 0) {
            q = a.divide(b); //Tính q = a/b lấy phần nguyên
            t = b;
            b = a.mod(b);  //Tính b mới = a mod b
            a = t; // Gán a bằng b lúc trước
            t = x0;
            x0 = x1.subtract(q.multiply(x0)); //tính lại x0= x1-(q*x0) //Có thể hiểu x0 là x(i-1) còn x1 là x(i-2) trong công thức
            x1 = t; //Gán x1 bằng x0 lúc trước
        }
        if (x1.compareTo(BigInteger.ZERO) < 0) x1 = x1.add(b0);
        return x1;
    }

    //Hàm tính x^n mod m bằng phương pháp đệ quy.
    public BigInteger pow(BigInteger x, BigInteger n, BigInteger m) {
        if (n.equals(BigInteger.ZERO)) return BigInteger.ONE;

        BigInteger temp = pow(x, n.divide(BigInteger.valueOf(2)), m);
        if (n.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) return temp.multiply(temp).mod(m);
        return temp.multiply(temp).mod(m).multiply(x).mod(m);
    }

    //Hàm tìm UCLN của 2 số nguyên lớn 
    public BigInteger gcd(BigInteger a, BigInteger b) {
        // Nếu b = 0, thì a là ước số chung lớn nhất
        if (b.equals(BigInteger.ZERO)) {
            return a;
        } else {
            // Đệ quy: GCD(a, b) = GCD(b, a % b)
            return gcd(b, a.mod(b));
        }
    }
    public void KeyRSA() {
        this.setN(this.getP().multiply(this.getQ()));
        BigInteger phi = (this.getP().subtract(BigInteger.ONE)).multiply(this.getQ().subtract(BigInteger.ONE));
        Random random = new Random();
        BigInteger r = phi.subtract(BigInteger.valueOf(1));
        BigInteger randomNumber = new BigInteger(r.bitLength(), random).mod(r).add(BigInteger.valueOf(2));

//        while (!isPrime(randomNumber)) {
//            randomNumber = new BigInteger(r.bitLength(), random).mod(r).add(BigInteger.valueOf(2));
//        }
        
        while (!gcd(randomNumber, phi).equals(BigInteger.ONE)) {
            randomNumber = new BigInteger(r.bitLength(), random).mod(r).add(BigInteger.valueOf(2));
        }
        this.setE(randomNumber);
        this.setD(mul_inv(getE(), phi));
    }

    public String encrypt(String message, BigInteger D, BigInteger N) {
        BigInteger x = BigInteger.ZERO;
        StringBuilder mahoa = new StringBuilder();
        char[] p = message.toCharArray();
        for (int i = 0; i < p.length; i++) {
            if (p[i] < 58) {
                BigInteger tem = BigInteger.valueOf((int) (p[i]) - 48);
                x = this.pow(tem, D, N);
                mahoa.append(x).append("-");
            } else {
                BigInteger tem = BigInteger.valueOf((int) (p[i]) - 87);
                x = this.pow(tem, D, N);
                mahoa.append(x).append("-");
            }
        }
        mahoa.deleteCharAt(mahoa.length() - 1);
        return mahoa.toString();
    }

    public String decrypt(String message, BigInteger E, BigInteger N) throws Exception{
        String[] parts = message.split("-");//phân tách chuỗi bằng dấu gạch ngang
        StringBuilder giaima = new StringBuilder();// Tạo một đối tượng StringBuilder để xây dựng chuỗi kết quả của quá trình giải mã.
        BigInteger y;//Khai báo một biến y để lưu trữ giá trị BigInteger từ mỗi phần của chuỗi đã tách.
        for (String part : parts) {
            if (part != null && !part.isEmpty()) {
                y = new BigInteger(part);//Chuyển đổi mỗi phần từ chuỗi thành một đối tượng BigInteger.
                BigInteger temp = this.pow(y, E, N);// Sử dụng phương thức pow để tính lũy thừa của y với E (số mũ) và N (modulus).
                if (temp.compareTo(BigInteger.TEN) < 0) {//Nếu giá trị tính toán (temp) nhỏ hơn 10, thì nó được thêm trực tiếp vào StringBuilder giaima.
                    giaima.append(temp);
                } else {
                    giaima.append((char) (temp.intValue() + 87));
                    //Nếu giá trị tính toán (temp) lớn hơn hoặc bằng 10, nó được chuyển đổi thành một ký tự tương ứng và được thêm vào StringBuilder.
                }
            }
        }
        return giaima.toString();
    }
}
