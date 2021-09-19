# API
### Thử thách:
- Easy and simple API: https://api.chal.acsc.asia
- [Source code](https://github.com/antoinenguyen-09/All_CTF_write-ups/tree/master/Asian%20Cyber%20Security%20Challenge%20(ACSC)/2021/web/source)
### Kiến thức nền:
- Broken Access Control.
### Giải quyết vấn đề:

1/ Chuẩn bị:

Như mọi dạng bài cho source code từ trước, việc đầu tiên chúng ta cần làm là tôn trọng tác giả, mở source code ra đọc và deploy nó lên. Vào trong root folder **public** rồi deploy trên locahost bằng lệnh `php -S localhost:<any port number>`. Tạm thời chưa quan tâm đến các file config như 000-default.conf, docker-compose.yml hay Dockerfile, chúng ta sẽ sử dụng sau. Nhìn sơ qua thì chúng ta có một cái web app chỉ có 3 chức năng thế này:
- Sign in:

![image](https://user-images.githubusercontent.com/61876488/133934895-b5532fed-052d-4091-813c-0811899547aa.png)

- Sign up:

![image](https://user-images.githubusercontent.com/61876488/133934921-6cf702a6-158a-48d0-b663-dea407eb46fb.png)

- Trang admin (không hiểu sao không cần sign in cũng vào được, nhưng mà nhìn chung nó cũng vô dụng):

![image](https://user-images.githubusercontent.com/61876488/133935020-edde6565-282c-41b6-b0c4-0e6d804ce934.png)

2/ Những cú lừa có thể sẽ gặp:

Bài này nhìn chung là khá dễ, nếu thậm chí nếu bạn đọc code và suy nghĩ theo cách đơn giản thì sẽ ra flag cực kì nhanh. Nhưng tôi và thằng teammate [baolongv3](https://github.com/baolongv3) đã chọn cách khó hơn, đó là ăn hết tất cả cú lừa của bài này:

a) Author để lộ tất cả các file trong private folder **db**:
- Không biết là vô tình hay cố ý mà tác giả lại để lộ 2 cái file "mới nhìn tưởng là quan trọng và là chìa khóa để tìm ra flag" này:
\+ user.db: file chứa toàn bộ thông tin account của tất cả các user trên web app này, mỗi field thông tin khác nhau được ngăn cách bởi dấu **|** (theo tôi dự đoán thì nó theo format sau: **username|hash của password|user level (admin sẽ được gán bằng 1, normal user được gán bằng 0)**). Khi refresh trang thì ta thấy file được append thêm một số account mới. Tất cả các account này đều có user level bằng 0. Chỉ duy nhất account có username tên **Pang** (trong hình) có user level bằng 1. 

![image](https://user-images.githubusercontent.com/61876488/133935426-9b75a34d-b2da-462d-8c76-261ecc974c5d.png)

File user.db được 

\+ passcode.db: phần

![image](https://user-images.githubusercontent.com/61876488/133935507-09c1781e-b1c1-45be-b0db-fabec655923b.png)


