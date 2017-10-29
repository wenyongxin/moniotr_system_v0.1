#!/usr/bin/env python
#ecoding:utf-8

import urllib,urllib2,cookielib,time,sys





def download_image(graphid,screenid):
        login_opt = urllib.urlencode({"name":user,"password":password,"autologin":1,"enter":"Sign in"})
        get_graph_opt = urllib.urlencode({"graphid":graphid,"screenid":"49","width":1200,"height":200,"period":259200,"stime":stime})
        cj = cookielib.CookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        login_url = r"%s/index.php" % url
        save_graph_url = r"%s/chart2.php" % url
        data = opener.open(save_graph_url,get_graph_opt).read()
        filename = "%s/%s.png" %(save_graph_path,graphid)
        f = open(filename,"wb")
        f.write(data)
        f.close()
        return filename
