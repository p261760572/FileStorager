//生成终端主密钥TMK DES(K0/K1）国密(QK/QL)
//功能  生成终端主密钥，并将其密文和检查值返回给主机。
//说明  生成的终端主密钥符合奇校验。
//入口参数
//sek_index:SEK索引,S＋4位索引
//tek_index:TEK索引,T＋4位索引
//flag 0：国密 1:DES 64 2:DES 128 3 DES 192
//出口参数
//return_code:返回码
//sek_tmk_data:TMK密文1,用SEK加密
//tek_tmk_data:TMK密文2,用TEK加密
//chk_tmk_data:TMK较验值
int GET_TMK(char *return_code, char *sek_index, char *tek_index, unsigned char flag, char *sek_tmk_data, char *tek_tmk_data, char *chk_tmk_data) {
	return 0;
}








//生成数据密钥PIK/MAK DES(K2/K3）国密(QT/QU)
//功能  生成数据密钥PIK/MAK，并将其密文和检查值返回给主机。
//说明  对于生成的数据密钥（PIK、MAK）需要同时各生成两对密文，其中一对用TMK加密用于通过联机报文方式在签到应答消息中传给终端，另一对用SEK加密后，将密文保存在数据库中。
//入口参数
//sek_index1:SEK1索引,用于解密TMK
//sek_index2:SEK2索引,用于加密PIK/MAK
//tmk:TMK密文,用SEK1加密
//tmk_flag 0:国密 1:DES 64 2:DES 128 3 DES 192
//pm_flag 0:国密 1:DES 64 2:DES 128 3 DES 192 [tmk为国密时pkdmak只能为国密,tmk为DES时pikmak只能为DES]
//出口参数
//return_code:返回码
//sek_pikmak_data:PIK/MAK密文1,用SEK2加密
//tmk_pikmak_data:PIK/MAK密文2,用TMK加密
//CheckValue:校验值
int GET_WORK_KEY(char *return_code, char *sek_index1, char *sek_index2, char *tmk, unsigned char tmk_flag, unsigned char pm_flag, char *sek_pikmak_data, char *tmk_pikmak_data, char *CheckValue) {
	return 0;
}

/*
DES_TO_RSA_KEY :
密钥原来由DES算法加密保护，通过此函数转换为RSA算法加密并输出加密结果。

*/

int DES_TO_RSA_KEY(char *return_code, char *sek_index, char *key, int ras_length, char *rsa_key, int *out_length, char *out_data) {
	return 0;
}


/*
DES_TO_MD5：
 密钥原来由DES算法保护，通过此函数获得明文再与数据合并做MD5算法，并输出MD5结果
*/
int DES_TO_MD5(char *return_code, char *sek_index, char *key, int in_length, char *in_data, int *out_length, char *out_data)
{
	return 0;
}

