/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package btljava;

/**
 *
 * @author ADMIN
 */
import java.security.*;

public class SHA1 {

    //nhận vào chuỗi text và trả về giá trị băm sd thuật toán SHA-1(hệ hex)
    public static String hash(String text) throws NoSuchAlgorithmException {
        // Tạo đối tượng MessageDigest với thuật toán SHA-1
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        // Cập nhật đối tượng MessageDigest với dữ liệu đầu vào
        sha1.update(text.getBytes()); //chuyển đổi chuỗi thành mảng byte và cập nhật

        // Tính toán bản tiêu đề SHA-1
        byte[] hash = sha1.digest();   //Mảng byte này có độ dài cố định là 20 byte cho SHA-1.

        //Tạo một đối tượng StringBuilder để xây dựng chuỗi hex.
        StringBuilder hexHash = new StringBuilder();
        // Chuyển đổi giá trị băm từ dạng byte sang dạng hex
        for (byte b : hash) {
             // Định dạng mỗi byte thành hai ký tự hex và thêm vào chuỗi hexHash
            hexHash.append(String.format("%02x", b)); 
        }
        return hexHash.toString();//in kq dưới dạng chuỗi hex
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.println(hash("Manh"));
    }
}
