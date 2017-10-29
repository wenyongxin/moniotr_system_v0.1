#!/usr/bin/env python
#ecoding:utf-8

import xlsxwriter
import os
import sys
reload(sys)
sys.setdefaultencoding( "utf-8" )



def mkdir_file(filepath):
	workbook = xlsxwriter.Workbook(filepath)
	return workbook	


def mkdir_worksheet(workbook,sheetname="sheetname"):
	worksheet = workbook.add_worksheet(sheetname)
	return worksheet

'''用于端口扫描文档生成'''
def mkdir_excel(workbook, worksheet, data, title, special_port):
	format = workbook.add_format({'bold':True})
	open = workbook.add_format()
	open.set_bg_color('red')

	style = workbook.add_format()
	style.set_align('vcenter')
	style.set_text_wrap()
	worksheet.write_row('A1', title, format)
	data_len = []
	for n, d in enumerate(data):
		worksheet.write_row(('A%s' %(int(n) + 2)), d, style)
		data_len.append(len(d))
		if special_port:
			for s_port in special_port:
				try:
					worksheet.write(int(n) + 1, int(d.index(s_port)), s_port, open)
				except:
					pass
	worksheet.set_column(0, 0, 50) 
	worksheet.set_column(1, max(data_len), 20) 


'''用于故障报告生成'''
def refule_report(workbook, worksheet, title, data, heads):
	worksheet.set_row(2,38)
	worksheet.write('C1',(u'核心服务故障时间（分钟）：%s' % heads[0]))
	worksheet.write('C2',(u'稳定性：%s%%' % heads[1]))
	worksheet.write('I1',(u'非核心服务故障时间（分钟）：%s' % heads[2] ))
	worksheet.write('I2',(u'稳定性：%s%%' % heads[3]))

	Deep_blue = workbook.add_format()
	Deep_blue.set_bg_color('#4F81BD')
	Deep_blue.set_font_size('11')
	Deep_blue.set_font_name(u'微软雅黑')
	Deep_blue.set_align('center')
	Deep_blue.set_align('vcenter')
	Deep_blue.set_font_color('#FFFFFF')
	Deep_blue.set_border(1)
	Deep_blue.set_text_wrap()


	orange = workbook.add_format()
	orange.set_bg_color('#E46D0A')
	orange.set_font_size('11')
	orange.set_font_name(u'微软雅黑')
	orange.set_align('center')
	orange.set_align('vcenter')
	orange.set_font_color('#FFFFFF')
	orange.set_border(1)
	orange.set_text_wrap()

	Light_blue = workbook.add_format()
	Light_blue.set_bg_color('#C5D9F1')
	Light_blue.set_font_size('11')
	Light_blue.set_font_name(u'微软雅黑')
	Light_blue.set_align('center')
	Light_blue.set_align('vcenter')
	Light_blue.set_border(1)
	Light_blue.set_text_wrap()

	bk = workbook.add_format()
	bk.set_border(1)
	bk.set_text_wrap()


	worksheet.write_row('A3', title, Deep_blue)
	worksheet.write_row('A3', title[:-2], Light_blue)
	worksheet.write_row('A3', title[:-10], Deep_blue)
	worksheet.write_row('A3', title[:-12], orange)
	worksheet.write_row('A3', title[:-14], Deep_blue)
	
	bk = workbook.add_format()
	bk.set_border(1)
	bk.set_text_wrap()
	bk.set_align('center')
	bk.set_align('vcenter')


	format2 = workbook.add_format()
	format2.set_num_format(0x0F)

	
	wide = [12.5, 34, 35.38, 14, 16.88, 10.75, 21, 12.63, 20.38, 28, 18, 15, 12.38, 15, 7.38, 42, 17.38, 12.25]
	for i,w in enumerate(wide):
		worksheet.set_column(i, i, w)

	for n, d in enumerate(data):
                worksheet.write_row(('A%s' %(int(n) + 4)), d, bk)


'''月度报告整理'''
def month_refule_report(workbook, worksheet):
	tital1_width = [17.88, 17.88, 16.5, 24, 22.13] 
	for i, w in enumerate(tital1_width):
		worksheet.set_column(i, i, w)


	A1 = workbook.add_format()
	A1.set_font_size('22')
	A1.set_font_name(u'宋体')
	A1.set_font_color('#7B7B7B')
	worksheet.write('A1',u'用户体验数据指标(用户可用率)',A1)

	A2 = workbook.add_format()
	A2.set_font_size('12')
        A2.set_font_name(u'微软雅黑')
        A2.set_font_color('#7B7B7B')
        worksheet.write('A2',u'年度可用率基准值暂定为99%，各项指标可用率均超过99%，处于可接受范围',A2)

	A3_Text = ['',u'产品/平台', u'指标项', '故障时间（分钟）', u'月度可用率']
	A3 = workbook.add_format()
	A3.set_bg_color('#5CB4B0') #背景颜色
	A3.set_font_size('16') #文字字号
	A3.set_font_name(u'微软雅黑') #文字字体
	A3.set_font_color('#FFFFFF') #文字颜色
	A3.set_align('center') #水平居中
	A3.set_align('vcenter') #垂直居中
	A3.set_border(1) #边框
	worksheet.write_row('A3', A3_Text, A3)
	worksheet.set_row(2, 45) # 设置行高 从0算起

	A4_A15 = workbook.add_format()
	A4_A15.set_align('center')
	A4_A15.set_align('vcenter')
	A4_A15.set_font_size('14')
	A4_A15.set_font_name(u'微软雅黑')
	A4_A15.set_border(1)
	worksheet.merge_range('A4:A15', u'一级指标', A4_A15)

	B4_B7 = workbook.add_format()
	B4_B7.set_align('center')
	B4_B7.set_align('vcenter')
	B4_B7.set_font_size('14')
	B4_B7.set_font_name(u'微软雅黑')
	B4_B7.set_border(1)
	worksheet.merge_range('B4:B7', u'港台', B4_B7)

	B8_B11 = workbook.add_format()
	B8_B11.set_align('center')
	B8_B11.set_align('vcenter')
	B8_B11.set_font_size('14')
	B8_B11.set_font_name(u'微软雅黑')
	B8_B11.set_border(1)
	worksheet.merge_range('B8:B11', u'韩国', B8_B11)

	B12_B15 = workbook.add_format()
	B12_B15.set_align('center')
	B12_B15.set_align('vcenter')
	B12_B15.set_font_size('14')
	B12_B15.set_font_name(u'微软雅黑')
	B12_B15.set_border(1)
	worksheet.merge_range('B12:B15', u'韩国', B12_B15)

	C4_Text = [u'登录', u'储值', u'注册', u'游戏故障', u'登录', u'储值', u'注册', u'游戏故障', u'登录', u'储值', u'注册', u'游戏故障']
	C4 = workbook.add_format()
	C4.set_align('center')
        C4.set_align('vcenter')
        C4.set_font_size('14')
        C4.set_font_name(u'微软雅黑')
        C4.set_border(1)
	worksheet.write_column('C4',C4_Text,C4)
	
	A16_Text = [u'二级指标', u'其他业务', u'管理后台']
	A16 = workbook.add_format()
        A16.set_align('center')
        A16.set_align('vcenter')
        A16.set_font_size('14')
        A16.set_font_name(u'微软雅黑')
        A16.set_border(1)
	worksheet.write_row('A16', A16_Text, A16)

	A17_C17 = workbook.add_format()
        A17_C17.set_align('center')
        A17_C17.set_align('vcenter')
        A17_C17.set_font_size('14')
        A17_C17.set_font_name(u'微软雅黑')
	A17_C17.set_bold()
	A17_C17.set_border(1)
	worksheet.merge_range('A17:C17', u'合计', A17_C17)

	'''至此A1-A17的页面元素已经配置完毕。可变动数据还未填写'''


	
	A19 = workbook.add_format({'font_size':'12', 'font_name':u'微软雅黑', 'font_color':'#7B7B7B'})
	#A19.set_font_size('12')
	#A19.set_font_name(u'微软雅黑')
	#A19.set_font_color('#7B7B7B')
	worksheet.write('A19',u'目标未达到：月度不正常服务时间占比 1.69%【目标为1%】',A19)

	

	
	
	

	
	


def close_file(workbook):
	workbook.close()



def main():
	filepath = 'test.xlsx'
	workbook = xlsxwriter.Workbook(filepath)
	worksheet = workbook.add_worksheet()
	month_refule_report(workbook, worksheet)
	workbook.close()

	

	





if __name__=='__main__':
	main()
