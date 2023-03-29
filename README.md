# SVATTT PTIT 2023
-----
## Overview

| Title | Category | Flag |
|---|---|---|
| Pwn01 | Pwn |  |
| Pwn02 | Pwn |  |
| Re1 | RE |  |
| Re2 | RE |  |
| Re3 | RE |  |
| Web1 | Web | `ATTT{3z_X2S_Fr0m_V@tv069_W1th_L0v3}` |
| Web2 | Web | `ATTT{4_51mpl3_r3v_5ql}` |
| Web1-Again | Web |  |
| Crypto1 | Cryptography | `ATTT{Meow_meow_meow_meow_tra_lai_tam_tri_toi_day}` |
| Crypto2 | Cryptography | `ATTT{NOT_A_SUBSTITUTION_CIPHER}` |
| For1 | Forensics | `ATTT{https://www.youtube.com/watch?v=4qNALNWoGmI}` |

# Forensics: For1

#### Challenge

<p> Flag Form: ATTT{This_is_Flag} <p>

[Ez4Ence.rar](https://github.com/vinhxinh/SVATTT_PTIT_2023/raw/main/For1/Ez4Ence.rar)

#### Solution

* Đề bài cho ta rất nhiều file rác không liên quan và 1 file chứa flag ta cần tìm.
* Sử dụng `grep` để tìm flag theo form có sẵn.

![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/For1/cmd1.jpg?raw=true)

**Flag**: `ATTT{https://www.youtube.com/watch?v=4qNALNWoGmI}`

# Cryptography: Crypto1

#### Challenge

[enc.cpp](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto1/enc.cpp)
[bases.txt](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto1/bases.txt)

#### Solution

<p> Đề bài cho ta 2 file bases.txt và enc.cpp. Đọc thử trong code ta thấy file bases.txt đã được encrypt 1 lần. Flag được encrypt bằng cách với 4 kí tự được chọn, kí tự 1 được mã hóa về octal, kí tự 2 và 4 mã hóa về decimal và kí tự 3 được mã hóa về dạng hexadecimal. Vậy với file bases.txt được cho ban đầu, ta sẽ tìm ngược lại flag đã được mã hóa <p>

![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto1/anh1.jpg?raw=true)

![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto1/anh2.jpg?raw=true)

**Flag**: `ATTT{Meow_meow_meow_meow_tra_lai_tam_tri_toi_day}`

# Cryptography: Crypto2

#### Challenge

<p> Do you know the substitution cipher? In cryptography, a substitution cipher is a method of encrypting in which units of plaintext are replaced with the ciphertext. CTF players often use quipqiup tool to decrypt substitution cipher. If you want to create a tool like quipqiup, you should use frequency analysis method as an aid to breaking substitution ciphers. But today is not the day for subtitution cipher. Today I'm using AES encryption to protect my secret. Can you break it? <p>

[cipher.txt](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto2/cipher.txt) 
[enc.py](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto2/enc.py)

* Đề bài cho 1 file cipher và source enc.

``` 
from os import urandom
from Crypto.Cipher import AES

f = open("plain.txt", "r")
plaintext = f.read()

assert all([x.isupper() or x in '.,-_{ }' for x in plaintext])


class Cipher:
    def __init__(self):
        self.salt = urandom(15)
        key = urandom(16)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, message):
        return [self.cipher.encrypt(c.encode() + self.salt) for c in message]


def main():
    cipher = Cipher()
    encrypted = cipher.encrypt(plaintext)
    encrypted = "\n".join([c.hex() for c in encrypted])

    with open("cipher.txt", 'w+') as f:
        f.write(encrypted)


if __name__ == "__main__":
    main()

```

* Nhìn vào cipher và source enc có thể thấy plaintext là 1 đoạn văn bản khoảng 1000 ký tự và nó bị mã hóa như sau:
  * Đầu tiên `assert` để kiểm tra tất cả ký tự trong file plain.txt. Nếu toàn bộ các ký tự thỏa mãn một trong hai điều kiện sau thì chương trình có thể tiếp tục chạy:
    * Điều kiện 1: Ký tự là chữ in hoa trong bảng chữ cái từ A đến Z.
    * Điều kiện 2: Ký tự là 1 trong số 7 kí tự đặc biệt chấm/phẩy/gạch trên/gạch dưới/mở/đóng ngoặc nhọn/dấu cách    `.,-_{} `
  * Tiếp theo đi thẳng vào vấn đề chính
  	```	
  	def encrypt(self, message):
  		return [self.cipher.encrypt(c.encode() + self.salt) for c in message]
  	```
  * Hàm encrypt thực hiện mã hóa bằng cách lấy mỗi ký tự trong bản rõ nối với chuỗi salt random gồm 15 ký tự tạo thành 1 chuỗi 16 ký tự (vừa đủ cho 1 khối). Sau đó chuỗi này sẽ được tiến hành mã hoá bằng thuật toán AES theo chế độ ECB.
  * Sau đó mỗi ký tự mã hóa xong đc in ra trên 1 dòng. Kết quả là file cipher có 1076 dòng = 1076 ký tự bị mã hóa.
  * Đến phần giải, đầu tiên là cơ chế mã hóa của AES mode ECB: **_ECB là chế độ mã hóa từng khối bit độc lập. Với cùng một khóa mã K, mỗi khối plaintext ứng với một giá trị ciphertext cố định và ngược lại_**.

    ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto2/pic1.jpg?raw=true)

  * Tức là với các ký tự giống nhau sau khi mã hóa sẽ ra được những bản mã giống nhau
  * Tiếp đến là đoạn code mã hóa này không hề làm thay đổi thứ tự ký tự của bản rõ vì thế có thể giải mã bằng phương pháp phán đoán như này:
     * Trước tiên kiểm tra file cipher bằng cách sử dụng uniq và đã lọc ra được 32 bản mã khác nhau đại diện cho 32 ký tự được mã hóa **A-Z.,-_{ }** (tổng có 33 ký tự có thể 1 ký tự nào đó đã không được sử dụng)
     * Dựa vào form flag **ATTT{ABC_DEF}** kiểm tra vị trí từng bản mã và duy nhất **79baa5dd638b9dd358e0ebd73a2f04d5** xuất hiện liên tiếp 3 lần và từ đó lọc được bản mã của A{}

    ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto2/pic2.jpg?raw=true)
     * **79baa5dd638b9dd358e0ebd73a2f04d5 = T**
     * **c7a8b2b718344a552973e2194f54316e = A**
     * **110da0235675bc52e3d3a20b65ee2d69 = {**
     * **a143b07765f0c492802cccbe10c2ad2d = }**
  * Tiếp tục mò ký tự _ vì là ký tự đặc biệt nên khả năng nó sẽ xuất hiện ít và khả năng xuất hiện bên ngoài form flag cũng rất ít
     * **7334d85f5c104c2b0f8318d371f94819 = _**
     * Vì nó xuất hiện chỉ 3 lần và đều nằm trong form flag

     ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto2/pic3.jpg?raw=true)
     * Sau đó thay thế mỗi bản mã khác nhau còn lại thành 1 ký tự khác nhau sẽ được như sau
     
     ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto2/pic4.jpg?raw=true)
     
     * Sau đó thử ném nội dung flag lên _quipqiup_ thì cũng được kha khá kết quả
    
     ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto2/pic5.jpg?raw=true)
     
     * Phần 3 từ đầu có vẻ khớp với **'not_a_substitution'**
    
     ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto2/pic6.jpg?raw=true)
  * Đến đây còn duy nhất 2 ký tự cuối trong cụm **"?I???"**. Đến đây thì thử các từ sao cho có nghĩa là được. 1 người biết tiếng Anh chắc chắn không mất nhiều lần để đoán ra đó là từ **"Cipher"** đâu nhỉ.

**Flag**: `ATTT{NOT_A_SUBSTITUTION_CIPHER}`
