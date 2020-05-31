#!/usr/bin/env python
# coding: utf-8

# # Реализация алгоритма BBS : Blum — Blum — Shub

# In[1]:


import math
import datetime
from accessify import private


# In[2]:


class BBS:
    def __init__(self, length: int = 64, q: int = None, p: int = None):
        """
        Класс генерации случайной последовательности длины length
        :param length: длина последовательности
        :param q: секретный q
        :param p: секретный p
        """
        self.length = length
        self.__p = p if p else 11
        self.__q = q if q else 19
        self.__M = self.__p * self.__q
        self.listSimpleNumber = []
        for i in range(2, self.__M):
            if self.__M % i != 0:
                self.listSimpleNumber.append(i)

    @private
    def generate(self) -> str:
        '''
        Фнкция создает последовательность длины length
        :return: Возвращает 2ичную последовательность длины length
        '''
        self.__x = self.listSimpleNumber[datetime.datetime.now().microsecond % len(self.listSimpleNumber)]
        self.X = [self.__x ** 2 % self.__M]
        self.result = str(self.X[0] % 2)
        for i in range(self.length - 1):
            self.X.append(
                self.X[i] ** 2 % self.__M
            )
            self.result += str(self.X[i + 1] % 2)

        return self.result

    def run(self):
        '''
        Запуск функции генерации
        :return: Возвращает 2ичную последовательность длины length
        '''
        return self.generate()
