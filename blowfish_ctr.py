#!/usr/bin/env python
# coding: utf-8

# 
# # Реализация Шифрования blowfish
# # c CTR

from mpmath import mp
import more_itertools
import copy
import secrets
from accessify import private



class Blowfish:
    def __init__(self):
        self.add_suf = 0
        self.LEN_PI = 20000 #Длина Числа ПИ
        mp.dps = self.LEN_PI #Установка числа длины ПИ
        self.PI = int((mp.pi - int(mp.pi))*10**self.LEN_PI) #Берем мантису числа ПИ
        self.PI_HEX = hex(self.PI)[2:8336+2] #Переводим в 16 систему

        self.FIXED_P = [''.join(i) for i in more_itertools.grouper(self.PI_HEX[:8*18],8)] #Матрица Раундовых ключей

        #Матрица подстановок
        self.FIXED_S = [i for i in more_itertools.grouper([''.join(i) for i in more_itertools.grouper(self.PI_HEX[8*18:],8)],256)]
        self.FIXED_S = [list(i) for i in self.FIXED_S]

    @private
    def F(self, block32:str, S:list):
        '''
        Функция итерации
        :param block32: Входной блок 32бит
        :paran S: Матрица подстановок
        :return: Результат функции итерации
        '''
        block32 = '{0:08x}'.format(int(block32,16))

        X1 = int(block32[0:2],16)
        X2 = int(block32[2:4],16)
        X3 = int(block32[4:6],16)
        X4 = int(block32[6:8],16)

        return hex(((((int(S[0][X1],16) + int(S[1][X2],16) ) % 2**32 ) ^ int(S[2][X3],16)) + int(S[3][X4],16)) % 2**32)[2:]

    @private
    def blowfishEncryptBlock(self, left32:str, right32:str, P:list, S:list)->list:
        '''
        :param left32: Левые 32 бита входного 64 блока
        :param right32: Правые 32 бита входного 64 блока
        :param P: Раундовые ключи
        :param S: Подстановочные ключи
        :return: Зашифрованный 64 бит блок
        '''
        for i in range(16):
            left32 = '{0:08x}'.format(int(left32,16) ^ int(P[i],16))
            right32 = '{0:08x}'.format(int(self.F(str(left32), S),16) ^ int(right32,16))
            left32, right32 = right32, left32

        left32, right32 = right32, left32
        right32 = (int(right32,16) ^ int(P[16], 16))
        left32 = (int(left32,16) ^ int(P[17], 16))

        return '{0:08x}'.format(left32),'{0:08x}'.format(right32)

    @private
    def blowfishDecryptBlock(self, left32:str, right32:str, P:list, S:list)->list:
        '''
        :param left32: Левые 32 бита входного 64 блока
        :param right32: Правые 32 бита входного 64 блока
        :param P: Раундовые ключи
        :param S: Подстановочные коючи
        :return: Расшифрованный 64 бит блок
        '''

        for i in range(17,1,-1):
            left32 = '{0:08x}'.format(int(left32,16) ^ int(P[i],16))
            right32 = '{0:08x}'.format(int(F(str(left32), S),16) ^ int(right32,16))
            left32, right32 = right32, left32

        left32, right32 = right32, left32
        right32 = '{0:08x}'.format(int(right32,16) ^ int(P[1], 16))
        left32 = '{0:08x}'.format(int(left32,16) ^ int(P[0], 16))

        return left32, right32

    @private
    def generateKeyBytes(self, key:str, len_result_key:int)->list:
        '''
        Функция переводи ключ в список байт. Если ключ меньше длины раундовых ключей, конкатинируем -> keykeykey
        :param key:  Входной ключ
        :param len_result_key: Длина выходного ключа, кол-во блоков
        : Результат создания ключа
        '''
        result = []
        key = key if key else 0
        for i in range(len_result_key * 4):
            result.append(
                '{0:04x}'.format(ord(key[i%len(key)]))
            )
        # print('key=',result)
        return [''.join(i) for i in more_itertools.grouper(result,2)]

    @private
    def generateTextBytes(self, text:str, len_block:int = 8)->list:
        '''
        Функция переводит текст в список байт. Если текст меньше длины кратной len_block то дополняем '0'
        :param text:  Входной текст
        :param len_block: Длина блока в битах
        : Результат создания списка текста 64бит
        '''

        self.add_suf = -len(text)%len_block
    #     print(add_suf)
        result = []
        text = text +'0'*(self.add_suf)
    #     print(len(text))
        for i in range(len(text)):
            result.append(
                '{0:04x}'.format(ord(text[i]))
            )
        # print(result)
        return [''.join(i) for i in more_itertools.grouper(result,4)]

    @private
    def generateRoundKey(self, P:list, key_bytes:list):
        '''
        Функция создающая раундовые ключи. Берет раундовый ключи P1 P2 ... и XOR c ключом
        :param P: Раундовые ключи
        :param key: Ключ
        : Результат создания ключа
        '''
        result_p = []
        for p,k in zip(P, key_bytes):
            result_p.append(
                hex((int(p,16)) ^ (int(k,16)))[2:]
            )

        return result_p

    @private
    def generateAllKey(self, P:list, S:list):
        '''
        Функция создающая итоговые Раундовые и Подстановочные ключи
        :param P: Раундовые ключи
        :param S: Подстановочные ключи
        : Результат - Раундовые и Подстановочные ключи
        '''
        NEW_P = copy.deepcopy(P)
        NEW_S = copy.deepcopy(S)

        tmp = None
        for i in range(0,17,2):
            if not tmp:
                    tmp = self.blowfishEncryptBlock(left32='0000', right32='0000', P=P, S=S)
            else:
                tmp = self.blowfishEncryptBlock(left32=tmp[0], right32=tmp[1], P=P, S=S)

            P[i] = tmp[0]
            P[i+1] = tmp[1]

        for i in range(4):
            for j in range(0,255,2):
                tmp = self.blowfishEncryptBlock(left32=tmp[0], right32=tmp[1], P=P, S=S)
                S[i][j] = tmp[0]
                S[i][j+1] = tmp[1]

        return P, S

    @private
    def generateIV(self) -> list:
        '''
        :return: Возвращает уникальную гамму размером 32 бит
        '''
        return secrets.token_hex(4) + '0'*8

    @private
    def encrypt(self, text_bytes:list,P:list,S:list, IV:str = None):
        '''
        Шифрование текста
        :param text_bytes: Открытый текст
        :param P:Матрица раундовых ключей
        :param S:Матрица подстановок
        :param IV: Блок гаммы длинной 64 бит
        :return: Закрытый текс
        '''
        if not IV:
            encrypt_text = ''
            for i in text_bytes:
                tmp = self.blowfishEncryptBlock(left32=i[0:8],right32=i[8:],P=P,S=S)
                encrypt_text+=(tmp[0]+tmp[1])
        else:
            CTR = IV
            encrypt_text = ''
            for i in text_bytes:
                IVL,IVR  = self.blowfishEncryptBlock(left32=CTR[0:8],right32=CTR[8:],P=P,S=S)
                encrypt_text += '{0:016x}'.format(int(IVL+IVR,16) ^ int(i,16))
                CTR = '{0:016x}'.format(int(CTR,16)+1)

        return encrypt_text

    @private
    def decrypt(self,text_bytes:list,P:list,S:list, IV:list = None):
        '''
        Шифрование текста
        :param text_bytes: Открытый текст
        :param P:Матрица раундовых ключей
        :param S:Матрица подстановок
        :param IV: Блок гаммы
        :return: Открытый текс
        '''
        if not IV:
            decrypt_text = ''
            for i in text_bytes:
                tmp = self.blowfishDecryptBlock(left32=i[0:8],right32=i[8:],P=P,S=S)
                decrypt_text+=(tmp[0]+tmp[1])
        else:
            CTR = IV
            decrypt_text = ''
            for i in text_bytes:
                IVL,IVR  = self.blowfishDecryptBlock(left32=CTR[0:8],right32=CTR[8:],P=P,S=S)
                decrypt_text += '{0:016x}'.format(int(IVL+IVR,16) ^ int(i,16))
                CTR = '{0:016x}'.format(int(CTR,16)+1)

        return decrypt_text


    def runEncrypt(self,open_text:str,key:str):
        '''
        Функция запуска Шифрования
        :param open_text: Открытый текст
        :param key: Ключ
        :return: Результат дополонительные 0 + шифрования + IV
        '''
        # Считываем ключ, переводим в список 32 бит, генерируем раундовые ключи
        self.key_bytes = self.generateKeyBytes(key, len_result_key=len(self.FIXED_P))
        self.NEW_FIXED_P = self.generateRoundKey(P=self.FIXED_P, key_bytes=self.key_bytes)

        # Генерируем раундовые и подстановочные ключи
        self.NEW_FIXED_P, self.NEW_FIXED_S = self.generateAllKey(self.NEW_FIXED_P, self.FIXED_S)

        # Считываваем по 64 бит Входного текста
        self.text_bytes = self.generateTextBytes(open_text)

        self.IV = self.generateIV()
        self.encrypt_text = self.encrypt(text_bytes=self.text_bytes,P=self.NEW_FIXED_P,S=self.NEW_FIXED_S,IV=self.IV)

        return str(self.add_suf)+","+self.encrypt_text+","+self.IV

    def runDecrypt(self,close_text:str,key:str):
        '''
        Функция запуска Дешифрования
        :param close_text: Закрытый текст
        :param key: Ключ
        :return: Результат дешифрования
        '''
        # Считываем ключ, переводим в список 32 бит, генерируем раундовые ключи
        self.key_bytes = self.generateKeyBytes(key, len_result_key=len(self.FIXED_P))
        self.NEW_FIXED_P = self.generateRoundKey(P=self.FIXED_P, key_bytes=self.key_bytes)

        # Генерируем раундовые и подстановочные ключи
        self.NEW_FIXED_P, self.NEW_FIXED_S = self.generateAllKey(self.NEW_FIXED_P, self.FIXED_S)


        self.add_suf, self.encrypt_text, self.IV = close_text.split(',')

        # print(self.add_suf, self.encrypt_text, self.IV)
        self.decrypt_text = (self.encrypt(text_bytes=[''.join(i) for i in more_itertools.grouper(self.encrypt_text,16)],
                                          P=self.NEW_FIXED_P,S=self.NEW_FIXED_S, IV=self.IV))

        result = ''

        for k in [''.join(i) for i in more_itertools.grouper(self.decrypt_text,4)]:
            result+=chr(int(k,16))

        result = result[:-int(self.add_suf)]

        return result






