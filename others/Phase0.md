ترم یکم داخل فایل های متنی توضیحات لازم داده شده . برای این ترم دروس یادگیری ماشین کاربردی ، امنیت شبکه پیشرفته ، امنیت و حریم خصوصی داده و سمینار دارم و باید تا اخر ترم یک پروپزوالم را سعی کنم به تصویب برسونم.

به کگل و گیت هاب دسترسی دارم . کولب هم فکر نکنم مشکلی باشه ولی tryhackme را تست نکرده ام.

3 ساعت برای شروع خوبه اگر دیدم وقت بیشتری دارم یا اگر برنامه های دانشگاهم سنگین شد بهت اطلاع میدم.

vmware را روی سیستم نصب دارم و داخلش یک کالی ، یه اوبونتو ، دوتا ویندوز 7 ، یک ویندوز ایکس پی نصب شده دارم. ویندوز خودمم 11 هستش.
ساخت مخزن هم در گیت هاب کاری نداره و سریعا انجامش دادم.

درکولب دستورات زیر را به ترتیب اجرا کردم :
pwd

cat > mytext.txt
hello my name is Alireza . I want to write a script to counting how many "faild
I want to write a script to counting how many "failed password" are in this text.
failed password
failed password
failed password
failed password
^C

ls

f = open("mytext.txt")
a = "failed password"
f.seek(0)
b = f.read()
x = 0
step = len(a)
for i in range(len(b) - step + 1) :
  if a == b[i:i+step]: x+=1
print (x)

a = "failed password"
f.seek(0)
b = f.read()
x = b.count(a)
print (x)