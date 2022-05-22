#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, redirect, session
from flask_wtf import FlaskForm

from wtforms.validators import DataRequired, length
from wtforms import TextAreaField, BooleanField, StringField, RadioField
from wtforms.widgets import PasswordInput

from flask_session.__init__ import Session
from datetime import date, timedelta

import sqlite3
import os
import logging
import hashlib

app = Flask(__name__)
app.debug = True
app.secret_key = 'xkHslGePyeA'
SESSION_TYPE = 'filesystem'

app.config.from_object(__name__)
Session(app)

curDir = os.path.abspath(os.path.dirname(__file__))
pathNotesDB = os.path.join(curDir,'notes.db')
pathUserDB = os.path.join(curDir, 'users.db')

logging.basicConfig(level=logging.DEBUG)





class noteForm(FlaskForm):
	note = TextAreaField('Poznámka', validators=[DataRequired(), length(max=250)])
	private = BooleanField('Private?')
	priority = RadioField("Priorita", choices=[('Nízká', '<br>Nízká'), ('Normální', '<br>Normální'), ('Vysoká', '<br>Vysoká')])

class logForm(FlaskForm):
	username = StringField("name", validators=[DataRequired()], render_kw={"placeholder": "  Jméno"})
	password = StringField("pass", validators=[DataRequired()], render_kw={"placeholder": "  Heslo"}, widget=PasswordInput(hide_value=False))

class regForm(logForm):
	confirmPass = StringField("pass", validators=[DataRequired()], render_kw={"placeholder": "  Potvrdit heslo"}, widget=PasswordInput(hide_value=False))



def getFormatedTime(year, month, day, hour, minute):
	noteDate = year + "-" + month + "-" + day
	if(str(date.today() - timedelta(hours=1, minutes=0)) == noteDate):
		timeStr = hour + ":" + minute
	else:	
		months = ["Jan", "Feb", "Mar", "Apr", "May", "June", "July", "Aug", "Sept", "Oct", "Nov", "Dec"]
		timeStr = year + " " + day.lstrip("0") + " " + months[int(month)-1]
	return timeStr

def sqliteCMD(cmd, var, wantReturn, db):
	if not wantReturn:
		conn = sqlite3.connect(db)
		c = conn.cursor()
		c.execute(cmd, var)
		conn.commit()
		conn.close()
	else:
		if var == None:
			conn = sqlite3.connect(db)
			c = conn.cursor()
			result = c.execute(cmd).fetchall()
			conn.commit()
			conn.close()
			return result
		else:
			conn = sqlite3.connect(db)
			c = conn.cursor()
			result = c.execute(cmd, var).fetchall()
			conn.commit()
			conn.close()
			return result

def getNotes(noteArr):
	for i in range(len(noteArr)):
		notes[i][1] = noteArr[i][1].replace('\r\n', '<br>')
		date = noteArr[i][2][:-3].replace(" ", "-").replace(":", "-").split("-")
		notes[i][2] = getFormatedTime(date[0], date[1], date[2], date[3], date[4])
	return notes



@app.route('/poznamka/vlozit', methods=['GET', 'POST'])
def addNote():
	"""Zobrazí folrmulář a vloží poznámku."""
	form = noteForm()
	noteText = form.note.data
	isPublic = form.private.data
	priority = form.priority.data

	logged = False
	if not 'logged' in session:
		name = "public"
		isPublic = True
	else:
		logged = session['logged']
		if not logged:
			name = "public"
			isPublic = True

	if form.validate_on_submit():

		if logged:
			name = session['user']
		else:
			name = "public"
			isPublic = True

		sqliteCMD("INSERT INTO note(body, private, owner, priority) VALUES (?,?,?,?)", (noteText, int(not isPublic), name, priority), False, pathNotesDB)
		return redirect('/')

	return render_template('addNote.html', form=form)

@app.route('/')
def showNotes():
	"""Zobrazí všechny poznamky."""
	logged = False
	if not 'logged' in session:
		name = "public"
		session['logged'] = 0;
		login = "Login"
		register = "Registrovat"
		logout = ""
		user = ""

	else:
		logged = session['logged']
		if logged:
			user = name = session['user']
			login = ""
			register = ""
			logout = "Odhlásit"
		else:
			name = "public"
			login = "Login"
			register = "Registrovat"
			logout = ""
			user = ""

	notesDB = sqliteCMD("SELECT rowid, body, kdy, private, owner, priority FROM note WHERE owner=? or private=0 ORDER BY kdy DESC", (name,), True, pathNotesDB)
	notes = [list(i) for i in notesDB]

	for i in range(len(notesDB)):
		notes[i][1] = notesDB[i][1].replace('\r\n', '<br>')
		date = notesDB[i][2][:-3].replace(" ", "-").replace(":", "-").split("-")
		notes[i][2] = getFormatedTime(date[0], date[1], date[2], date[3], date[4])
		if (name == notes[i][4] or name == "Dalibor") and name != "public":
			notes[i][4] = ["Del", "Edit"]
		else:
			notes[i][4] = ["",""]
		notes[i][5] = notesDB[i][5]
	

	return render_template('showNotes.html', notes=notes, login=login, register=register, logout=logout, user=user)

@app.route('/del/<int:noteID>')
def deleteNote(noteID):
	"""Smaže vybranou poznámku"""
	sqliteCMD("DELETE FROM note WHERE rowid=?", (noteID,), False, pathNotesDB)
	return redirect('/')

@app.route('/poznamka/upravit/<int:noteID>', methods=['GET', 'POST'])
def editNote(noteID):
	"""Upravý vybranou poznámku"""
	form = noteForm()
	noteText = form.note.data
	isPublic = form.private.data
	priority = form.priority.data

	logged = False
	if not 'logged' in session:
		name = "public"
		isPublic = True
	else:
		logged = session['logged']
		if not logged:
			name = "public"
			isPublic = True

	if form.validate_on_submit():

		if isPublic and logged:
			name = session['user']
		elif not isPublic and logged:
			name = session['user']
		else:
			name = "public"
			isPublic = True

	note = sqliteCMD("SELECT body FROM note WHERE rowid=?", (noteID,), True, pathNotesDB)
	form.note.data = list(note)[0][0]

	if form.validate_on_submit():
		sqliteCMD("UPDATE note SET body=? WHERE rowid=?", (noteText, noteID), False, pathNotesDB)
		sqliteCMD("UPDATE note SET private=? WHERE rowid=?", (int(not isPublic), noteID), False, pathNotesDB)
		#sqliteCMD("UPDATE note SET owner=? WHERE rowid=?", (name, noteID), False, pathNotesDB)
		sqliteCMD("UPDATE note SET priority=? WHERE rowid=?", (priority, noteID), False, pathNotesDB)
		return redirect('/')

	return render_template('addNote.html', form=form, noteID=noteID)


@app.route('/<string:user>/profile', methods=['GET', 'POST'])
def profile(user):

	notesDB = sqliteCMD("SELECT rowid, body, kdy, private, owner, priority FROM note WHERE owner=? ORDER by kdy DESC", (user,), True, pathNotesDB)
	dateDB = list(sqliteCMD("SELECT regDate FROM users WHERE name=?", (user,), True, pathUserDB))

	dateRaw = dateDB[0][0][:-3].replace(" ", "-").replace(":", "-").split("-")

	notes = [list(i) for i in notesDB]
	for i in range(len(notesDB)):
		notes[i][1] = notesDB[i][1].replace('\r\n', '<br>')
		date = notesDB[i][2][:-3].replace(" ", "-").replace(":", "-").split("-")
		notes[i][2] = getFormatedTime(date[0], date[1], date[2], date[3], date[4])
		notes[i][4] = ["Del", "Edit"]
		notes[i][5] = notesDB[i][5]

	date = getFormatedTime(dateRaw[0], dateRaw[1], dateRaw[2], dateRaw[3], dateRaw[4])

	return render_template('profile.html', user=user, date="Účet vytvořen: " + date, notes=notes, logout="Odhlásit")

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = logForm()
	warn = ""

	if form.validate_on_submit():

		username = form.username.data
		password = hashlib.sha1(form.password.data.encode('utf-8')).hexdigest()
		passHash = sqliteCMD("SELECT pass FROM users WHERE name=?", (username,), True, pathUserDB)
		passHash = [ list(i) for i in passHash]
		passHash = passHash[0][0]
		app.logger.info(passHash)

		if not passHash:
			warn = "Uživatel neexistuje"
		elif password == passHash:
			#logged in
			session['user'] = username
			session['logged'] = True

			return redirect('/')
		else:
			warn = "Nesprávné jméno nebo heslo"


	return render_template('login.html', form=form, warn=warn)

@app.route('/register', methods=['GET', 'POST'])
def register():
	form = regForm()

	warn = "Hesla jsou zašifrována pomocí SHA1"

	if form.validate_on_submit():
		username = form.username.data
		password = hashlib.sha1(form.password.data.encode('utf-8')).hexdigest()
		passwordConfirm = hashlib.sha1(form.confirmPass.data.encode('utf-8')).hexdigest()

		exists = sqliteCMD("SELECT name from users WHERE name=?", (username, ), True, pathUserDB)

		if exists: 
			warn = "Jméno není dostupné"
		elif password == passwordConfirm:
			sqliteCMD("INSERT INTO users(name, pass) VALUES (?, ?)", (username, password), False, pathUserDB)
			session['user'] = username
			session['logged'] = True
			return redirect('/')
		else:
			warn = "Hesla se musí shodovat"

	return render_template('register.html', form=form, warn=warn)


@app.route('/<string:user>/logout', methods=['GET', 'POST'])
def logOut(user):
    session['logged'] = False
    session[user] = ""
    return redirect('/')

if __name__ == '__main__':
	app.run()



