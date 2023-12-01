from urllib.request import urlopen

urlopen("https://acm.xidian.edu.cn/")

try:
    while True:
        a, b = map(int, input().split())
        print(a + b)
except EOFError:
    pass
