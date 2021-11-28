# simpleWAF


[Source](https://github.com/antoinenguyen-09/All_CTF_write-ups/tree/master/ISITDTU%20CTF/2021/web/simpleWAF/source)


Đây là challenge web đầu và cũng là dễ nhất trong 4 challenge của ISITDTU CTF năm nay. Dù vậy vì một số lí do ngu người nên mất cả buối sáng mình mới solve đc bài này.

### 1. Initial reconnaissance:

![image](https://user-images.githubusercontent.com/61876488/143764818-b63dd063-04cf-4de2-afe7-6fa69f0d859c.png)

- Nhìn qua challenge này cho hẳn source với rất nhiều regex, cùng với một cái url parameter to tướng ở phía trên tên là **XSS** thì chắc chắn hướng đi sẽ là từ [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) lấy cookie của client. 
- Đề bài còn cho biết: `if you can steal cookie, bot will check it at here`, nghĩa là sau khi exploit lấy cookie thành công từ site chính rồi, chúng ta sẽ submit payload cho con bot dưới đây check xem có hợp lệ và nếu đúng nó sẽ trả cho chúng ta flag.

![image](https://user-images.githubusercontent.com/61876488/143770699-6dc9cc9b-9879-4be6-a6ca-186c8bac69c4.png)

### 2. Analyze and find the vulnerabilities:

- Đầu tiên, website sẽ lấy ra string từ url parameter `xss` rồi check xem nó đã đc url encode chuẩn chưa (thông qua vòng while). Sau đó nếu như trong string đó có các [HTML entities](https://www.w3schools.com/html/html_entities.asp) thì nó sẽ trở về dạng ban đầu thông qua hàm 

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







