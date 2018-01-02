from random import randint
import random
import string
import xlsxwriter
from fpdf import FPDF
import os.path
from shutil import copyfile


# .xls Files
def randomxls(path):
    numxls = (randint(10, 20))

    for i in range(10):

        name = path + ''.join(
            [random.choice(string.ascii_letters + string.digits) for n in range(randint(5, 15))]) + ".xlsx"

        workbook = xlsxwriter.Workbook(name)
        worksheet = workbook.add_worksheet()

        numrows = (randint(10, 50))

        for i in range(numrows):
            coord = 'A' + str(i)

            textinrow = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(randint(5, 15))])

            worksheet.write(coord, textinrow)

        workbook.close()

        for i in range(numxls):
            dupli = path + ''.join(
                [random.choice(string.ascii_letters + string.digits) for n in range(randint(5, 15))]) + ".xlsx"

            copyfile(name, dupli)


# .pdf Files + .txt Files
def randompdf(path):
    numpdf = (randint(15, 20))

    for i in range(10):

        name = path + ''.join(
            [random.choice(string.ascii_letters + string.digits) for n in range(randint(5, 15))]) + ".pdf"
        name1 = path + ''.join(
            [random.choice(string.ascii_letters + string.digits) for n in range(randint(5, 15))]) + ".txt"
        fh = open(name1, "w+")

        numwords = (randint(10, 20))

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        words = []

        for i in range(numwords):
            randomword = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(randint(5, 15))])
            fh.write(randomword + "\n")
            words.append(randomword)

        fh.close()
        wordsinstring = ''.join(words)

        pdf.cell(200, 10, txt=wordsinstring, align="C")

        pdf.output(name)

        for i in range(numpdf):
            dupli = path + ''.join(
                [random.choice(string.ascii_letters + string.digits) for n in range(randint(5, 15))]) + ".pdf"
            dupli1 = path + ''.join(
                [random.choice(string.ascii_letters + string.digits) for n in range(randint(5, 15))]) + ".txt"

            copyfile(name, dupli)
            copyfile(name1, dupli1)


randomxls(os.environ['USERPROFILE'] + "\\Desktop\\honey\\")
randompdf(os.environ['USERPROFILE'] + "\\Desktop\\honey\\")
