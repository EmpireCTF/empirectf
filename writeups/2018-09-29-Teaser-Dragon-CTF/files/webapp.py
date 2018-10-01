import functools

import flask

import backend
import flask_session
import model
from waitress import serve

sql_session = backend.sql_session

_GET = ['GET']
_POST = ['POST']

CAPTCHA_ENABLED = False

K_LOGGED_IN = 'logged_in'
K_LOGGED_USER = 'logged_user'
K_CIPHERKEY = 'userdata'
K_AUTH_USER = 'auth_user'
K_CAPTCHA = 'captcha_solution'

app = flask.Flask(__name__)
backend.setup_app(app)

session_obj_handle = flask_session.Session(app)


class WebException(Exception):
  pass


def get_required_params(where, fields, soft_fail=False):
  kw = {}
  src = None
  if where == 'GET':
    src = flask.request.args
  if where == 'POST':
    src = flask.request.form
  for vn in fields:
    val = src.get(vn, None)
    if val is None:
      if soft_fail:
        return None
      else:
        raise WebException("Required argument '{0}' is missing !".format(vn))
    kw[vn] = val
  return kw


def _context():
  return dict(
    meta_tags=[],
    messages=flask._msg,
    username=flask.session.get(K_LOGGED_USER, None),
    appname="DrgnS|Ent3rp4is S0lution"
  )


def do_render(**kw):
  ctx = _context()
  ctx['sid'] = flask.session.sid
  for key in kw:
    ctx[key] = kw[key]
  return flask.make_response(flask.render_template("index.html", ctx=ctx))


def do_302(target):
  return flask.make_response(flask.redirect(target))


def add_msg(text, style='info'):
  flask._msg.append(dict(
    text=text,
    style=style,
  ))


@app.route('/', methods=["POST", "GET"])
def do_default():
  return do_render()


@app.route('/reg', methods=['GET'])
def do_register_form():
  captcha, solution = backend.make_captcha()
  flask.session[K_CAPTCHA] = solution
  return do_render(view='reg.html', captcha=captcha)


@app.route('/reg', methods=['POST'])
def do_register_post():
  params = get_required_params("POST", ['login', 'passwd', 'solve'])
  good_sum = flask.session.get(K_CAPTCHA, -1)
  if CAPTCHA_ENABLED and params['solve'] != good_sum:
    add_msg('U fail at math ;-(')
  n = sql_session.query(model.Users).filter_by(username=params.get('login')).count()
  if n > 0:
    add_msg("User already exists !")
    return do_render()

  user = model.Users(
    username=params.get('login'),
    password=backend.password_hash(params.get('passwd')),
    motd="",
  )
  sql_session.add(user)
  sql_session.commit()
  backend.setup_user(params.get('login'))
  add_msg("User created ! login now !")
  return do_render()


@app.route('/login/user', methods=['GET'])
def do_login_user_form():
  do_logout()
  # app.session_interface.save_session()
  # if flask.session.get(K_LOGGED_IN):
  #  return
  return do_render(view='auth_user.html')


@app.route('/login/user', methods=['POST'])
def do_login_user_post():
  username = get_required_params("POST", ['login'])['login']
  backend.cache_save(
    sid=flask.session.sid,
    value=backend.get_key_for_user(username)
  )
  state = backend.check_user_state(username)
  if state > 0:
    add_msg("user has {} state code ;/ contact backend admin ... ".format(state))
    return do_render()
  flask.session[K_LOGGED_IN] = False
  flask.session[K_AUTH_USER] = username

  return do_302("/login/auth")


@app.route("/login/auth", methods=['GET'])
def do_auth_form():
  return do_render(view="auth_pass.html")


@app.route("/login/auth", methods=['POST'])
def do_auth_post():
  flask.session[K_LOGGED_IN] = False
  username = flask.session.get(K_AUTH_USER)
  params = get_required_params("POST", ["password", "token"])
  hashed = backend.password_hash(params['password'])
  record = sql_session.query(model.Users).filter_by(
    username=username,
    password=hashed,
  ).first()
  if record is None:
    add_msg("Fail to login. Bad user or password :-( ", style="warning")
    return do_render()
  # well .. not implemented yet
  if 1 == 0 and not backend.check_token(username, token=1):
    add_msg("Fail to verify 2FA !")
    return do_render()
  flask.session[K_LOGGED_IN] = True
  flask.session[K_LOGGED_USER] = record.username
  return do_302("/home/")


@app.route("/logout")
def do_logout():
  flask.session[K_LOGGED_USER] = ''
  flask.session[K_LOGGED_IN] = False
  return do_302("/")


def loginzone(func):
  @functools.wraps(func)
  def _wrapper(*a, **kw):
    if flask.session.get(K_LOGGED_IN):
      return func(*a, **kw)
    else:
      add_msg("Dude ! U R NOT logged in.")
      do_logout()
      return do_render()

  return _wrapper


@app.route("/home/")
@loginzone
def do_home():
  print(flask.session.sid)
  print(backend.cache_load(sid=flask.session.sid))
  perms = backend.check_permisions(flask.session.get(K_LOGGED_USER))
  return do_render(view="home.html", perms=perms)


@app.route("/note/list")
@loginzone
def do_note_list():
  cnt = sql_session.query(model.Notes).count()
  cur = flask.session.get(K_LOGGED_USER)
  notes = sql_session.query(model.Notes).filter_by(username=cur).order_by("id").limit(10).all()
  return do_render(view="notelist.html", notes=notes, notes_count=cnt)


@app.route("/note/getkey")
@loginzone
def do_note_getkey():
  return flask.jsonify(dict(
    key=backend.get_key_for_user(flask.session.get(K_AUTH_USER))
  ))


@app.route("/note/show/<idx>")
@loginzone
def do_note_show(idx):
  note = sql_session.query(model.Notes).filter_by(id=idx).first()
  # note = xor_note(note)
  return do_render(view="noteshow.html", note=note)


@app.route("/note/add", methods=['GET'])
@loginzone
def do_note_add_form():
  return do_render(view="addnote.html")


@app.route("/note/add", methods=['POST'])
@loginzone
def do_note_add_post():
  text = get_required_params("POST", ["text"])["text"]
  key = backend.cache_load(flask.session.sid)
  if key is None:
    raise WebException("Cached key")
  text = backend.xor_1337_encrypt(
    data=text,
    key=key,
  )
  note = model.Notes(
    username=flask.session[K_LOGGED_USER],
    message=backend.hex_encode(text),
  )
  sql_session.add(note)
  sql_session.commit()
  add_msg("Done !")
  return do_render()


@app.route('/favicon.ico')
def do_favicon():
  return flask.redirect('static/favicon.ico')


@app.before_request
def check_request():
  logged = flask.session.get(K_LOGGED_IN, None)
  if logged is None:
    # initialize stuff 
    do_logout()
  flask._msg = []
  pass


@app.errorhandler(WebException)
def handle_error(error):
  add_msg("Missing : " + str(error))
  return do_render()


# @app.errorhandler(Exception)
def handle_error2(error):
  sql_session.rollback()
  response = flask.Response("<h1>C'mon! It's broken :/</h1><p>{0}</p>".format(str(error)))
  response.status_code = 400
  # print(str(error))
  return response


if __name__ == "__main__":
  serve(app, port=8080)
