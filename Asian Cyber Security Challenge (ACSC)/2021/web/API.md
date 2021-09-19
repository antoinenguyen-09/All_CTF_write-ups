# API
### Thử thách:
- Easy and simple API: https://api.chal.acsc.asia
- [Source code](https://github.com/antoinenguyen-09/All_CTF_write-ups/tree/master/Asian%20Cyber%20Security%20Challenge%20(ACSC)/2021/web/source)
### Kiến thức nền:
- Broken Access Control.
### Giải quyết vấn đề:

1) Chuẩn bị:

Như mọi dạng bài cho source code từ trước, việc đầu tiên chúng ta cần làm là tôn trọng tác giả, mở source code ra đọc và deploy nó lên. Vào trong root folder **public** rồi deploy trên locahost bằng lệnh `php -S localhost:<any port number>`. Tạm thời chưa quan tâm đến các file config như 000-default.conf, docker-compose.yml hay Dockerfile, chúng ta sẽ sử dụng sau.

2) Những cú lừa có thể sẽ gặp:

Bài này nhìn chung là khá dễ, nếu thậm chí nếu bạn đọc code và suy nghĩ theo cách đơn giản thì sẽ ra flag cực kì nhanh. Nhưng tôi và thằng teammate [baolongv3](https://github.com/baolongv3) đã chọn cách khó hơn, đó là ăn hết tất cả cú lừa của bài này:

a. Author để lộ tất cả các file trong private folder **db**:


