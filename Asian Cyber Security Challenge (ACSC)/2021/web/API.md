# API
### Thử thách:
- Easy and simple API: https://api.chal.acsc.asia
- [Source code](https://github.com/antoinenguyen-09/All_CTF_write-ups/tree/master/Asian%20Cyber%20Security%20Challenge%20(ACSC)/2021/web/source)
### Kiến thức nền:
- Broken Access Control.
### Giải quyết vấn đề:

1/ Thăm dò:

Như mọi dạng bài cho source code từ trước, việc đầu tiên chúng ta cần làm là tôn trọng tác giả, mở source code ra đọc và deploy nó lên. Vào trong root folder **public** rồi deploy trên locahost bằng lệnh `php -S localhost:<any port number>`. Tạm thời chưa quan tâm đến các file config như 000-default.conf, docker-compose.yml hay Dockerfile, chúng ta sẽ sử dụng sau. Nhìn sơ qua thì chúng ta có một cái web app chỉ có 3 chức năng thế này:
- Sign in:

![image](https://user-images.githubusercontent.com/61876488/133934895-b5532fed-052d-4091-813c-0811899547aa.png)

- Sign up:

![image](https://user-images.githubusercontent.com/61876488/133934921-6cf702a6-158a-48d0-b663-dea407eb46fb.png)

- Trang admin (không hiểu sao không cần sign in cũng vào được, nhưng mà nhìn chung nó cũng vô dụng):

![image](https://user-images.githubusercontent.com/61876488/133935020-edde6565-282c-41b6-b0c4-0e6d804ce934.png)

Thử tạo một account tại **signup.html** rồi đăng nhập vào thử:

![image](https://user-images.githubusercontent.com/61876488/133984382-77054168-a985-4fe1-bb9f-ea2ba0d2e210.png)


2/ Nghiên cứu source code:

Bài này nhìn chung là khá dễ, nếu thậm chí nếu bạn đọc code và suy nghĩ theo cách đơn giản thì sẽ ra flag cực kì nhanh. Nhưng tôi và thằng teammate [baolongv3](https://github.com/baolongv3) đã chọn cách khó hơn, đó là ăn hết tất cả cú lừa của bài này.

Cú lừa đầu tiên, không biết là vô tình hay cố ý mà tác giả lại để lộ 2 cái file "mới nhìn tưởng là quan trọng và là chìa khóa để tìm ra flag" này:

- user.db: file chứa toàn bộ thông tin account của tất cả các user trên web app này, mỗi field thông tin khác nhau được ngăn cách bởi dấu **|** (theo tôi dự đoán thì nó theo format sau: **username|hash của password|user level (admin sẽ được gán bằng 1, normal user được gán bằng 0)**). Khi refresh trang thì ta thấy file được append thêm một số account mới. Tất cả các account này đều có user level bằng 0. Chỉ duy nhất account có username tên **Pang** (trong hình) có user level bằng 1. 

![image](https://user-images.githubusercontent.com/61876488/133935426-9b75a34d-b2da-462d-8c76-261ecc974c5d.png)

Nhìn vào hàm main, ta thấy file user.db vốn không có sẵn trong folder db. Nó được khởi tạo bằng cách gọi hàm **gen_user_db**:

```php
function gen_user_db($acc){
	$path = dirname(__FILE__).DIRECTORY_SEPARATOR;
	$path .= "db".DIRECTORY_SEPARATOR;
	$path .= "user.db";
	if (file_exists($path)) return false;
	else {
		global $admin;
		$u = new User($acc);
		$fmt = sprintf("%s|%s|%d,", $admin['id'], $u->gen_hash($admin['pw']), $admin['level']);
		file_put_contents($path, $fmt);
	}
}
``` 
Nếu file user.db chưa được tạo, nó sẽ được tạo mới bởi hàm [file_put_contents](https://www.w3schools.com/php/func_filesystem_file_put_contents.asp), đồng thời hàm này sẽ ghi vào file user.db mới được tạo account của admin thông qua biến $fmt, biến này lại lấy các field **id**, **pw** và **level** từ global array $admin được gọi từ file **config.php**:

```php
<?php
$admin = ['id' => "*secret*", 'pw' => "*secret*", 'level' => 1];
?>
```
Vậy là đúng như dự đoán, admin được gán level bằng 1, như vậy account có id là "Pang" chắc chắn là admin, và ta cần lấy được password của user này bằng cách dehash cái này: `c307cae832059f15e52cc5e6a26a2eb3ae7173e6`. Password được hash bằng hàm ripemd160:

```php
public function gen_hash($val){
	return hash("ripemd160", $val);
}
```

Nhưng có vẻ đây là một challenge dùng não 100%, đừng phí thời gian chạy hashcat hàng tiếng đồng hồ để tìm password như tôi nhé, nó không ra cái gì đâu @@

- passcode.db: chứa một string có độ dài 5 kí tự, nếu chỉ nhìn mà không đọc code kĩ thì sẽ rất dễ nhầm đây là salt mà tác giả ném vào hàm hash ripemd160 để băm password của các user. Nếu deploy đoạn code này (lấy từ hàm **gen_pass_db**) thì bạn sẽ đấy string này random từ biến $rand_str sau mỗi lần refresh trang:

```php
$rand_str = "`~1234567890-=!@#$%^&*()_+qwertyuiopT[]\\";
$rand_str .= "asdfghjkl;':\"zxcvbnm./<>?QWERASDFZCVBNM";
$res = '';
for($i = 0; $i < $len; $i++){
	$res .= $rand_str[rand(0, strlen($rand_str)) - 1];
}
echo $res;
```
Nhưng trên [url](https://api.chal.acsc.asia/lib/db/passcode.db) thì dù refresh lại bao nhiêu lần nó cũng ra ":<vNk". Lí do là vì file **passcode.db** cũng hoạt động giống file **user.db**, nếu file đã được tạo rồi thì hàm sẽ kết thúc và không đụng gì file nữa:

```php
if (file_exists($path)) return false;
```

![image](https://user-images.githubusercontent.com/61876488/133935507-09c1781e-b1c1-45be-b0db-fabec655923b.png)

=> Xem xong file này tôi có 2 thắc mắc:
  
  \- Hai hàm **gen_user_db** và **gen_pass_db** đều hoạt động giống y hệt nhau, tại sao refresh trang user.db thì thấy các account mới được append vào còn passcode.db thì vẫn giữ nguyên như vậy? Chứng tỏ có một hàm nào đó khác nữa đã làm công việc append này, và nó chính là hàm **signup** (check [file](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/Asian%20Cyber%20Security%20Challenge%20(ACSC)/2021/web/source/public/lib/User.class.php)):

```php
public function signup(){
	if (!preg_match("/^[A-Z][0-9a-z]{3,15}$/", $this->acc[0])) return false;
	if (!preg_match("/^[A-Z][0-9A-Za-z]{8,15}$/", $this->acc[1])) return false;
	$data = $this->load_db();
	for($i = 0; $i < count($data); $i++){
		if ($data[$i][0] == $this->acc[0]) return false;
	}
	file_put_contents($this->db['path'], $this->db['fmt'], FILE_APPEND);  // $this->db['path'] == 'public/lib/db/user.db' và $this->db['fmt'] = sprintf("%s|%s|%d,", $this->acc[0], $this->gen_hash($this->acc[1]), 0) 
	return true;
}
```
  
  \- Nếu ":<vNk" trong file **passcode.db** không phải là salt của hàm hash ripedm160, vậy nó được tạo ra để làm gì? Nhìn vào hàm **is_pass_correct** trong file [Admin.class.php](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/Asian%20Cyber%20Security%20Challenge%20(ACSC)/2021/web/source/public/lib/Admin.class.php), ta thấy $passcode lấy data từ file **passcode.db** thông qua hàm **get_pass**, $input lấy data từ value của parameter **pas** được lưu trên superglobal [REQUEST](https://www.w3schools.com/php/php_superglobals_request.asp), sau đó nếu 2 biến này bằng nhau thì `return true`:
  
```php
public function is_pass_correct(){
	$passcode = $this->get_pass();  // $passcode == ':<vNk'
	$input = $_REQUEST['pas'];
	if ($input == $passcode) return true;
}
```
  
3/ Khai thác:

- Nói thêm một chút về các parameter nằm trong superglobal **REQUEST** của bài này, tất cả đều được gửi từ form **signin** thông qua hàm signin nằm trong file [client.js](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/Asian%20Cyber%20Security%20Challenge%20(ACSC)/2021/web/source/public/static/js/client.js). Nếu theo luồng hoạt động của hàm này thì chỉ có 3 parameter được gửi vào **REQUEST** là **id**, **pw** và **c** (1). Như vậy, để hàm **is_pass_correct** có thể `return true`, ta phải tự chèn thêm parameter `pas=:<vNk` vào sau khi sign in (2).
- Như đã thấy ở phần **thăm dò**, dù có tạo được account thì chúng ta cũng không thể vào được bên trong, web app chỉ alert rằng "Only admin can access the page". Bắt thử một request rồi send qua repeater của Burp Suite thì ta được:

![image](https://user-images.githubusercontent.com/61876488/134211842-5dc017ee-08fe-4c6f-8a62-05180c5c84c1.png)

- Response cho biết rằng trang web đang bị chuyển hướng đến **/api.php?#access denied** do đoạn code javascript `location.href = '/api.php?#access denied';`. Vậy đoạn code javascript này từ đâu ra. Check hàm **main** rồi mò lại hàm **challenge**, ta có:
  
```php
$admin = new Admin();
if (!$admin->is_admin()) $admin->redirect('/api.php?#access denied');
$cmd = $_REQUEST['c2'];
if ($cmd) {
	switch($cmd){
		case "gu":
			echo json_encode($admin->export_users());
			break;
		case "gd":
			echo json_encode($admin->export_db($_REQUEST['db']));
			break;
		case "gp":
			echo json_encode($admin->get_pass());
			break;
		case "cf":
			echo json_encode($admin->compare_flag($_REQUEST['flag']));
			break;
	}
}
```
- Đọc lướt qua thì ta sẽ thấy đây là một đoạn code authorize rất bình thường, khi account không phải admin thì sẽ trả về response như đã thấy trên Burp Suite. Nhưng nhìn kĩ lại một chút thì chúng ta phát hiện một sai lầm cực kì tai hại của người viết đoạn code này, đó chính là dùng `if (!$admin->is_admin())` cho câu lệnh `$admin->redirect('/api.php?#access denied');` nhưng lại quên đặt các khối lệnh phía sau vào `else`. Điều này đồng nghĩa rằng kể cả account của bạn không phải là admin, đăng nhập vào bị alert ra lỗi, nhưng vẫn có thể thực thi toàn bộ các lệnh ở phía sau `if`. Vấn đề bây giờ chỉ là chọn value vào để 
  



  

