//�����ն�����ԿTMK DES(K0/K1������(QK/QL)
//����  �����ն�����Կ�����������ĺͼ��ֵ���ظ�������
//˵��  ���ɵ��ն�����Կ������У�顣
//��ڲ���
//sek_index:SEK����,S��4λ����
//tek_index:TEK����,T��4λ����
//flag 0������ 1:DES 64 2:DES 128 3 DES 192
//���ڲ���
//return_code:������
//sek_tmk_data:TMK����1,��SEK����
//tek_tmk_data:TMK����2,��TEK����
//chk_tmk_data:TMK����ֵ
int GET_TMK(char *return_code, char *sek_index, char *tek_index, unsigned char flag, char *sek_tmk_data, char *tek_tmk_data, char *chk_tmk_data) {
	return 0;
}








//����������ԿPIK/MAK DES(K2/K3������(QT/QU)
//����  ����������ԿPIK/MAK�����������ĺͼ��ֵ���ظ�������
//˵��  �������ɵ�������Կ��PIK��MAK����Ҫͬʱ�������������ģ�����һ����TMK��������ͨ���������ķ�ʽ��ǩ��Ӧ����Ϣ�д����նˣ���һ����SEK���ܺ󣬽����ı��������ݿ��С�
//��ڲ���
//sek_index1:SEK1����,���ڽ���TMK
//sek_index2:SEK2����,���ڼ���PIK/MAK
//tmk:TMK����,��SEK1����
//tmk_flag 0:���� 1:DES 64 2:DES 128 3 DES 192
//pm_flag 0:���� 1:DES 64 2:DES 128 3 DES 192 [tmkΪ����ʱpkdmakֻ��Ϊ����,tmkΪDESʱpikmakֻ��ΪDES]
//���ڲ���
//return_code:������
//sek_pikmak_data:PIK/MAK����1,��SEK2����
//tmk_pikmak_data:PIK/MAK����2,��TMK����
//CheckValue:У��ֵ
int GET_WORK_KEY(char *return_code, char *sek_index1, char *sek_index2, char *tmk, unsigned char tmk_flag, unsigned char pm_flag, char *sek_pikmak_data, char *tmk_pikmak_data, char *CheckValue) {
	return 0;
}

/*
DES_TO_RSA_KEY :
��Կԭ����DES�㷨���ܱ�����ͨ���˺���ת��ΪRSA�㷨���ܲ�������ܽ����

*/

int DES_TO_RSA_KEY(char *return_code, char *sek_index, char *key, int ras_length, char *rsa_key, int *out_length, char *out_data) {
	return 0;
}


/*
DES_TO_MD5��
 ��Կԭ����DES�㷨������ͨ���˺�����������������ݺϲ���MD5�㷨�������MD5���
*/
int DES_TO_MD5(char *return_code, char *sek_index, char *key, int in_length, char *in_data, int *out_length, char *out_data)
{
	return 0;
}

