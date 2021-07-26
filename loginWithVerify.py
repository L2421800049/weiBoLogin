import threading
import requests,json,re,base64,time,rsa,binascii
from lxml import etree

# 下面有一些方法属性没有用到，我就懒得删了，大佬们看看就好

class Wblogin():
    def __init__(self):
        self.session = requests.session()
        self.preDic = dict()
        self.loginDic = dict()
        self.ajaxUrl = ''
        self.session = requests.session()
        self.headers = {
            'Referer': 'https://mail.sina.com.cn/?from=mail',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362',
            'Cache-Control': 'max-age=0',
            'Accept': '*/*',
            'Accept-Language': 'zh-Hans-CN,zh-Hans;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Host': 'login.sina.com.cn',
            # 'Connection': 'Keep-Alive'
        }

    def preLogin(self,account):
        preLoginUrl = "https://login.sina.com.cn/sso/prelogin.php"
        params = {
            "entry": "cnmail",
            "callback": "sinaSSOController.preloginCallBack",
            "su": str(base64.b64encode(bytes(account, encoding="utf-8")), encoding="utf-8"),  # base64编码之后的用户账号
            "rsakt": "mod",
            "client": "ssologin.js(v1.4.19)",
            "_": str(int(time.time() * 1000))  # 时间戳
        }
        preRes = self.session.get(url=preLoginUrl,headers=self.headers,params=params)
        # 预登录拿到servertime nonce  pubkey rsakv
        # 正登录时要用
        res = json.loads(re.findall("{.*?\}",preRes.text)[0])
        print(res)
        print("=" * 20)
        self.preDic = res

    # rsa加密密码
    def encrypt_passwd(self,passwd, pubkey, servertime, nonce):
        key = rsa.PublicKey(int(pubkey, 16), int('10001', 16))
        message = str(servertime) + '\t' + str(nonce) + '\n' + str(passwd)
        passwd = rsa.encrypt(message.encode('utf-8'), key)
        return binascii.b2a_hex(passwd)

    def login(self,passwd):
        loginUrl = "https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)"
        params = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'qrcode_flag': 'false',
            'useticket': '1',
            'pagerefer': 'https',
            'vsnf': '1',
            'su': 'MTU2NzU0OTEyODQ=',
            'service': 'miniblog',
            'servertime': self.preDic['servertime'],
            'nonce': self.preDic['nonce'],  # 预登录拿到的东西
            'pwencode': 'rsa2',
            'rsakv': self.preDic['rsakv'],
            'sp': self.encrypt_passwd(passwd, self.preDic['pubkey'], self.preDic['servertime'], self.preDic['nonce']),
            'sr': '1536*864', # sp就是加密的密码
            'encoding': 'UTF-8',
            # 'prelt': '35',
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }

        logRes = self.session.post(url=loginUrl,headers=self.headers,params=params)
        logRes.encoding = logRes.apparent_encoding
        # 拿到通行证,通信证里面有token
        print(logRes.text)
        print("="*30)
        urls = re.findall("https://.*\"",logRes.text)
        ajaxUrl = urls[-1]
        # print(urls)
        # 这个ajaxurl就是一个包含token的url
        self.ajaxUrl = ajaxUrl
        ajaxUrl = ajaxUrl.split("?")[-1].split("&")
        for each in ajaxUrl:
            self.loginDic[each.split("=")[0]] = each.split("=")[1]

    def getScan(self):
        url = "https://passport.weibo.com/protection/index"
        print(self.loginDic)
        info = self.loginDic['protection_url']
        token = info.split("%3D")[-1][:-1] # 提取token
        print("token: ",token)
        callback_url="https://weibo.com/"
        # print(url+"?token="+token+"&callback_url="+callback_url)
        scanUrl = url+"?token="+token+"&callback_url="+callback_url
        # 正登录，到验证的界面
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Host': 'passport.weibo.com',
            'Referer': 'https://weibo.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.59',
        }
        res = self.session.get(url = scanUrl,headers=headers)
        res.encoding = res.apparent_encoding

        if "抱歉，出错啦！" not in res.text:
            verifyHtml = etree.HTML(res.text)
            veUrl = verifyHtml.xpath("//div[@id='avatar_dm']/text()")[0]
            print("账号密码正确,进入到了验证区域")
            self.verify(token,veUrl)
        else:
            print("失败")

    def verify(self,token,veUrl):
        # 请求验证
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br',
            "Connection": "keep-alive",
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'passport.weibo.com',
            'Origin': 'https://passport.weibo.com',
            'Referer': 'https://passport.weibo.com/protection/index?token={}&callback_url=https%3A%2F%2Fweibo.com'.format(token),
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.59',
            'X-Requested-With': 'XMLHttpRequest',
        }
        params = {
            "token":"{}".format(token)
        }
        url = "https://passport.weibo.com/protection/privatemsg/send"
        res = self.session.post(url = url,headers=headers,data=params)
        print(res.json())
        if res.json()['msg'] == "succ":
            print("请验证")
            self.verifyTickets(token)
        print("="*30)

    def verifyTickets(self,token):
        # 无线循环获取protection/privatemsg/getstatus HTTP/1.1消息
        while True:
            url = "https://passport.weibo.com/protection/privatemsg/getstatus"
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
                'Host': 'passport.weibo.com',
                'Referer': 'https://passport.weibo.com/protection/index?token={}&callback_url=https%3A%2F%2Fweibo.com'.format(token),
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.59',
            }
            data  = {
                "token": token,
            }
            res = self.session.post(url=url,headers=headers,data=data)
            # 这里拿到了ticket
            if res.json()['data']['status_msg'] == "验证成功":
                print(res.json())
                redirectionUrl = res.json()['data']['redirect_url']
                self.crossDomain1(redirectionUrl)
                break # 运行完了

    def crossDomain1(self, redirectionUrl):
        tc = ""
        login_time = ""
        sign = ""
        r = ""
        for each in redirectionUrl.split("?")[-1].split("&")[:-1]:
            print(each)
            if (each.split("=")[0] == "alt"):
                alt = each.split("=")[1]
                alt = re.sub("%3D", "=", alt).replace("ALT","ST")
        # print(alt)  # 处理alt
        # 拿到通行证
        url = "https://login.sina.com.cn/sso/login.php?entry=weibo&returntype=META&crossdomain=1&cdult=3&savestate=30&alt={}&url=https://weibo.com".format(alt.replace("ST","ALT"))
        # print("ssosavestate在这",url)
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.59",
            "Referer": "https://passport.weibo.com/",
            "Host": "login.sina.com.cn",
        }
        resp = self.session.get(url=url,headers=headers)
        resp.encoding = resp.apparent_encoding
        print("*"*30)
        print(resp.text)
#https://passport.weibo.com/wbsso/login?ssosavestate=1657625337&url=https%3A%2F%2Fweibo.com%3Fsudaref%3Dpassport.weibo.com&display=0&ticket=ST-NTk2Mzk0ODQ3NQ==-1626089337-tc-E1EB34A5381B89958820F173577BE419-1&retcode=0        # print("ssosavestate在这",resp.text)
        try:
            print("get infos")
            tc = re.findall("ST-NTk.*?[0-9A-Z]{32}-1",resp.text)[0]
            print(tc)
            sign = re.findall("sign=[0-9a-z]{16}",resp.text)[0].replace("sign=","")
            print(sign)
            login_time = re.findall("ssosavestate%3D[\d]{10}",resp.text)[0][-10:]
            print(login_time)
        except:
            pass
        r = "https://passport.weibo.com/wbsso/login?ssosavestate="+login_time+"&url=https%3A%2F%2Fweibo.com%3Fsudaref%3Dpassport.weibo.com&display=0&ticket="+tc+"&retcode=0"
        print("*" * 30)
        SUB = ""
        try:
            SUB = re.findall("SUB=.*?;",resp.headers['Set-Cookie'])[0][:-1].split("=")[-1]
        except:
            pass
        self.crossDomain2(url,login_time,sign,r,SUB)

    def crossDomain2(self,ref,login_time,sign,r,SUB):
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' ,
            'Accept-Encoding': 'gzip, deflate, br' ,
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6' ,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.59" ,
            "Referer": ref ,
            "Host": "passport.krcom.cn" ,
        }
        data = {
            "action":"login",
            "entry":"weibo",
            "r":r,
            "login_time":login_time,
            "sign":sign,
        }
        print(data)
        url = "https://login.sina.com.cn/crossdomain2.php"
        res = self.session.get(url=url,headers=headers,params=data)
        res.encoding = res.apparent_encoding
        print("+"*30)
        print(res.text)
        print("+"*30)
        ticket = re.sub("%3D","=",re.findall("ST-NTk.*?[0-9A-Z]{32}-1" , res.text)[0])
        ssosavestate = re.findall("ssosavestate=[\d]{10}",res.text)[0][-10:]
        print("new tickt")
        print(ssosavestate)
        self.ssoLogin(ticket,ssosavestate,SUB)

    def ssoLogin(self,ticket,ssosavestate,SUB):
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.59",
            "Referer": "https://login.sina.com.cn/",
        }
        cookies = {
            "SUB":SUB,
        }
        url = "https://passport.weibo.com/wbsso/login"
        data = {
            "ssosavestate": ssosavestate,
            "ticket": ticket,
            "callback": "sinaSSOController.doCrossDomainCallBack",
            "scriptId": "ssoscript0",
            "client": "ssologin.js(v1.4.19)",
            "_": str(int(time.time()*1000)),
        }
        print(data)
        res = self.session.get(url=url,params=data,headers = headers)
        res.encoding = res.apparent_encoding
        j = json.loads(re.findall("\{.+\}" , res.text)[0])
        print(j)
        if j["result"] == "true" or "True":
            print("sso登录成功")
            uniqueid = j['userinfo']['uniqueid']
            self.userProfile(uniqueid,SUB)
        else:
            print("sso登录失败")

    def userProfile(self,uniqueid,sub):
        url = "https://weibo.com/u/{}/home?wvr=5&sudaref=passport.weibo.com".format(uniqueid)
        headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.59",
            "referer": "https://login.sina.com.cn/",
            "path": "/u/{}/home".format(uniqueid),
            "authority": "weibo.com",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-encoding": "gzip, deflate, br",
        }
        res = self.session.get(url=url,headers = headers)
        res.encoding = res.apparent_encoding
        print("-"*30)
        print(res.text)
        if "id" in res.text: # 这个是id 你自己登录的时候需要把这个改了，改成你自己的
            print("成功进入主页")

            # 下面就是操作了
            #
            #
            #
            #
            # self.theNew(uniqueid)

            # self.rename(sub)

            self.coment()
        else:
            print("进入主页失败")
        print("-"*30)

    def coment(self):
        # 2141823055/Kg9t1qfGy
        headers = {
            # "x-xsrf-token": "QY9wgJozvuzhIeIbB890uf_Z",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.67",
            "referer": "https://weibo.com/6405076905/KlvccoK0c",
        }
        data = {
            "id": "Kg9t1qfGy"
        }
        url = "https://weibo.com/ajax/statuses/show"
        resp = self.session.get(url=url,headers=headers,params = data)
        id = resp.json()['id']
        uid = resp.json()['user']['id']


        data2 = {
            "id":id,
            "uid":uid,
            "is_reload":1,
            "is_show_bulletin":2,
            "count":"200"
        }
        url2 = "https://weibo.com/ajax/statuses/buildComments"
        resp2 = self.session.get(url=url2,headers=headers,params = data2)


        with open('./com.json',"w",encoding="utf-8") as f:
            f.write(json.dumps(resp2.json(),ensure_ascii=False))
        f.close()

        # 这个里面可以写回复评论的评论，不难，不想写了，主要参数是 这个用户一个id 原来评论的id 还有就是子评论那个参数
        # def heandleJson(infos):
        #     datas = infos['data']
        #     for each in datas:
        #         pubTime = ""
        #         text = ""
        #         comment_like = ""
        #         screen_name = ""
        #         location = ""
        #         comid = ""
        #         description = ""
        #         gender = ""
        #         try:
        #             # 发表时间
        #             pubTime = each['created_at']
        #         except:
        #             pass
        #         # 评论内容
        #         try:
        #             text = each['text']
        #         except:
        #             pass
        #         # 评论获赞数
        #         try:
        #             comment_like = each['like_counts']
        #         except:
        #             pass
        #         # 评论人的名字
        #         try:
        #             screen_name = each['user']['screen_name']
        #         except:
        #             pass
        #         # 评论人的为位置
        #         try:
        #             location = each['user']['location']
        #         except:
        #             pass
        #         # 评论人的id
        #         try:
        #             comid = each['user']['id']
        #         except:
        #             pass
        #         # 评论人的个签
        #         try:
        #             description = each['user']['description']
        #         except:
        #             pass
        #         # 评论人的头像url
        #         # 背景连接
        #         try:
        #             profile_image_url = each['user']['profile_image_url']
        #             cover_image_phone = each['user']['cover_image_phone']
        #         except:
        #             pass
        #         # 性别
        #         try:
        #             gender = each['user']['gender']
        #         except:
        #             pass
        #         # 评论人的粉丝和朋友 我也分不清
        #         # 都在这个user下面
        #         # friends_count = each['user']['friends_count']
        #         # followers_count = each['user']['followers_count']
        #         # print(comid)
        #         print(pubTime , text , comment_like , screen_name , location , comid , gender , description)
        #         # print(each)
        # heandleJson(resp2.json())
        # threading.Thread(target=heandleJson(resp2.json())).start()


    def rename(self,sub):
        url = "https://weibo.com/ajax/setting/updateProfileBasic"
        headers = {
            # xsrf认证
            "x-xsrf-token": "8NgaBe8prjcd6rA435leKnjO" ,
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.59",
            # "traceparent": "00-f18cf6409d8c5aa1a21403024b1e7051-3493b1294b2e47a6-00"
        }
        cookies = {
            "SUB":sub,
        }
        data = {"screen_name":"dasda"}
        res = self.session.post(url=url,headers=headers,data=data,cookies = cookies)
        print(res.text)


    # 最新微博
    def theNew(self,uid):
        url = "https://weibo.com/ajax/feed/friendstimeline"
        params = {
            # 这个参数可以xpath获取
            "list_id":"110005963948475",
            "fid":"110005963948475",
            "refresh":"4",
            "since_id": "50",
            "count": "10",
        }
        headers = {
            # xsrf认证
            "x-xsrf-token": "8NgaBe8prjcd6rA435leKnjO",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Edg/91.0.864.59"
        }
        res = self.session.get(url=url,headers=headers,params=params)
        res.encoding = res.apparent_encoding
        print("/"*30)
        print(res.json())
        print("/"*30)


    def main(self):
        account = ""
        passwd = ""
        self.preLogin(account)
        self.login(passwd)
        self.getScan()

if __name__ == '__main__':
    w = Wblogin()
    w.main()
