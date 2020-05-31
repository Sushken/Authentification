#!/usr/bin/env python
# coding: utf-8

# # Реализация протокола аутентификации на основе проверки пароля
# # С помошью шифрования Blowfish c режимом счетчика
# # И генерации ключа на основе ПДСЧ BBS Blum — Blum — Shub

# In[1]:


from blowfish_ctr import Blowfish
from bbs import BBS
import os
import sys
from accessify import private
import logging
import more_itertools
import json


# In[2]:


logging.basicConfig(format = u'%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.INFO)


# In[7]:


class Authentication:
    def __init__(self, len_key:int = 448, file_name:str='Include/DB.json'):
        '''
        Констркутор
        :param len_key: длина генерации ключа для Blowfish по умолчанию 448
        :param file_name: место нахождения файла хранения учеток
        '''
        if len_key>448 or len_key<32:
            logging.info('Длина ключа больше 448 ')
            self.len_key = 448
        else:
            self.len_key = len_key
        
        self.__main_dict = {'key':''}
        self.__file_name = self.resource_path(file_name)
        self.generateKey()
        self.__alarm = 0 
    
    @private
    def resource_path(self, relative):
        '''
        :return полный путь до файла
        '''
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, relative)
        else:
            return os.path.join(os.path.abspath("."), relative)
    
    
    @private
    def generateKey(self):
        '''
        Функция генерации ключа
        Ключ для blowfish от 32 до 448 бит
        '''
        
        self.__key = ''
        for j in [''.join(i) for i in more_itertools.grouper(BBS(self.len_key, 991, 997).run(),8)]:
            self.__key+=chr(int(j,2))

        self.__main_dict['key'] = self.__key
        
        if not os.path.exists(self.__file_name):
            logging.info('файл не существует')
            with open(self.__file_name, 'w', encoding='utf-8') as file:
                file.write(json.dumps(self.__main_dict))
            
            return self.__main_dict
            
        else:
            with open(self.__file_name, 'r', encoding='utf-8') as file:
                self.__main_dict = json.loads(file.read())
            if not self.__main_dict.get('key'):
                logging.info('Попытки взлома')
                self.__alarm = 1
            else:
                self.__key = self.__main_dict['key']
                self.__alarm = 0
                
            return self.__main_dict

    def check(self, login, password):
        if self.__alarm or login=='key':
            logging.info('попытки взлома Работать не буду')
            return 0
        
        if self.__main_dict.get(login):
            logging.info('Пользователь есть')

            if Blowfish().runDecrypt(self.__main_dict[login], self.__key) == password :
                logging.info('Вы аутентифицированны')
                return 1
            else:
                logging.info('Пароль не верный')
                return 0
        else:
            logging.info('Пользователь не найден')
            return 0

    def createUser(self, login, password):
        if self.__alarm:
            return 'попытки взлома Работать не буду'
        
        if login == 'key':
            logging.error('Запрещено')
            return 0
        
        if self.__main_dict.get(login):
            logging.info('Пользователь есть')
            return 1
        else:
            self.__main_dict[login] = Blowfish().runEncrypt(password,self.__key)
            logging.info('Новая запись добавлена')
            with open(self.__file_name,'w') as file:
                file.write(json.dumps(self.__main_dict, indent=4, sort_keys=True))
            return 0
