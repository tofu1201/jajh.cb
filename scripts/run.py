import subprocess

# 非同步執行兩個程式，兩者同時啟動
p1 = subprocess.Popen(['python', 'app.py'])
p2 = subprocess.Popen(['python', 'bot.py'])

p1.wait()
p2.wait()

print("兩個程式已經開始執行！")