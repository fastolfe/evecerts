import os

from google.appengine.api import app_identity, memcache, users
import jinja2
import webapp2

import cert_data
import skill_data
import user_data

jinja_environment = jinja2.Environment(
  loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))


class HomeHandler(webapp2.RequestHandler):

  def get(self):
    template = jinja_environment.get_template('index.html')
    self.response.out.write(template.render({}))


class APIKeysHandler(webapp2.RequestHandler):

  KEY_LIST_CACHE_KEY_FORMAT = "key-list-1-%s"

  def get(self):
    action = self.request.get('action')

    if action == 'refresh':
      return self.refresh_key()
    elif action == 'remove':
      return self.remove_key()

    return self.list_keys()

  def post(self):
    action = self.request.get('action')

    if action == 'add':
      return self.add_key()

    self.error(500)

  def list_keys(self):
    user = users.get_current_user()
    mc_key = self.KEY_LIST_CACHE_KEY_FORMAT % user.user_id()

    page = memcache.get(mc_key)

    if not page:
      keys = []
      for key in user_data.get_keys_for_user(user):
        key_data = {
          'id': key.key_id,
          'vcode': key.vcode,
          'characters': ", ".join(c.name for c in key.character_set),
        }
        keys.append(key_data)

      template = jinja_environment.get_template("apikeys.html")
      page = template.render({'keys': keys})
      memcache.set(mc_key, page)

    self.response.out.write(page)

  def add_key(self):
    user = users.get_current_user()
    key_id, vcode = self.request.get('id'), self.request.get('vcode')
    key_id = user_data.validate_key(key_id)

    if not (key_id and user_data.validate_vcode(vcode)):
      self.error(500)
      return self.response.out.write('key ID or vcode are invalid')

    if not user_data.add_key_for_user(user, key_id, vcode):
      # Key already existed
      return self.redirect("/apikeys")

    memcache.delete(self.KEY_LIST_CACHE_KEY_FORMAT % user.user_id())
    self.redirect("/apikeys?action=refresh&id=%d" % key_id)

  def remove_key(self):
    user = users.get_current_user()

    key_id = user_data.validate_key(self.request.get('id'))
    if not key_id:
      self.error(500)
      return self.response.out.write("Invalid key id.")

    user_data.remove_key_for_user(user, key_id)

    memcache.delete(self.KEY_LIST_CACHE_KEY_FORMAT % user.user_id())
    self.redirect("/apikeys")

  def refresh_key(self):
    user = users.get_current_user()
    key_id = user_data.validate_key(self.request.get('id'))
    if not key_id:
      self.error(500)
      return self.response.out.write("Invalid key id.")

    try:
      if not user_data.refresh_key_for_user(user, key_id):
        self.error(500)
        return self.response.out.write("Key ID was not known")
    except user_data.ApiKeyError as e:
      self.error(500)
      return self.response.write('Unable to refresh key: %s' % e.message)

    memcache.delete(self.KEY_LIST_CACHE_KEY_FORMAT % user.user_id())
    self.redirect("/apikeys")



class SkillTreeHandler(webapp2.RequestHandler):
  def get(self):
    try:
      treedata = skill_data.refresh_skill_tree()
    except skill_data.SkillTreeError as e:
      self.error(500)
      return self.response.out.write(e.message)

    self.response.out.write("Successfully retrieved skills for %d groups." %
      len(treedata))


class PublicCertificationsHandler(webapp2.RequestHandler):
  CERT_PUBLIC_LIST_CACHE_KEY = "cert-public-list"

  def get(self):
    return self.list_public_certs()

  def list_public_certs(self):
    mc_key = self.CERT_PUBLIC_LIST_CACHE_KEY
    page = memcache.get(mc_key)

    if not page:
      certs = cert_data.get_public_certs(limit=100)
      template = jinja_environment.get_template("public_certs.html")
      page = template.render({'certs': certs})
      memcache.set(mc_key, page)

    self.response.out.write(page)

class CertificationsHandler(webapp2.RequestHandler):

  CERT_LIST_CACHE_KEY_FORMAT = "cert-list-1-%s"
  SKILL_GROUPS_CACHE_KEY = 'skill-groups'

  def get(self):
    action = self.request.get('action')

    if action == 'edit':
      return self.edit_cert()
    elif action == 'remove':
      return self.remove_cert()
    elif action == 'removeskill':
      return self.remove_skill()
    elif action == 'togglelock':
      return self.toggle_lock()
    elif action == 'resetlink':
      return self.reset_link()

    return self.list_certs()

  def post(self):
    action = self.request.get('action')

    if action == 'add':
      return self.add_cert()
    elif action == 'addskill':
      return self.add_skill()

    self.error(500)

  def list_certs(self):
    user = users.get_current_user()
    mc_key = self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id()
    page = memcache.get(mc_key)

    if not page:
      certs = cert_data.get_certs_for_owner(user)
      template = jinja_environment.get_template("certs.html")
      page = template.render({'certs': certs})
      memcache.set(mc_key, page)

    self.response.out.write(page)

  def add_cert(self):
    user = users.get_current_user()
    try:
      cert = cert_data.create_cert(user, self.request.get('name'))
    except cert_data.CertNameInvalid as e:
      self.error(500)
      return self.response.out.write(e.message)

    memcache.delete(self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id())
    memcache.delete(PublicCertificationsHandler.CERT_PUBLIC_LIST_CACHE_KEY)

    self.redirect("/certs?action=edit&id=%d" % cert.key().id())

  def remove_cert(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))

    if cert_data.remove_cert(cert_id):
      memcache.delete(self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id())
      memcache.delete(PublicCertificationsHandler.CERT_PUBLIC_LIST_CACHE_KEY)

    self.redirect("/certs")

  def edit_cert(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))

    try:
      cert = cert_data.get_cert_if_owner(user, cert_id)
    except cert_data.PermissionDeniedError:
      return self.error(403)
    except cert_data.CertNotFoundError:
      return self.error(404)

    skill_tree, skill_names = skill_data.get_skill_data()
    skillgroups = skill_data.get_skill_groups(skill_tree)
    skills = cert_data.get_cert_skills_dict(cert, skill_names=skill_names)

    data = {
      'cert': cert,
      'skills': skills,
      'skillgroups': skillgroups,
    }

    template = jinja_environment.get_template("edit_cert.html")
    page = template.render(data)

    self.response.out.write(page)

  def add_skill(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))
    skill_id = int(self.request.get('skillid'))
    rank = int(self.request.get('rank'))

    try:
      cert_data.add_skill(user, cert_id, skill_id, rank)
    except cert_data.PermissionDeniedError:
      return self.error(403)
    except (cert_data.CertNotFoundError,
            cert_data.SkillNotFoundError,
            cert_data.InvalidRankError):
      return self.error(500)

    return self.redirect("/certs?action=edit&id=%d" % cert_id)

  def remove_skill(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))
    skill_id = int(self.request.get('skillid'))

    try:
      cert_data.remove_skill(user, cert_id, skill_id)
    except cert_data.PermissionDeniedError:
      return self.error(403)

    return self.redirect("/certs?action=edit&id=%d" % cert_id)

  def toggle_lock(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))

    try:
      cert_data.toggle_lock(user, cert_id)
    except cert_data.PermissionDeniedError:
      return self.error(403)

    memcache.delete(self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id())
    memcache.delete(PublicCertificationsHandler.CERT_PUBLIC_LIST_CACHE_KEY)

    return self.redirect("/certs")

  def reset_link(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))

    try:
      cert_data.reset_link(user, cert_id)
    except cert_data.PermissionDeniedError:
      return self.error(403)

    memcache.delete(self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id())

    return self.redirect("/cert?id=%d" % cert_id)


class CertificationHandler(webapp2.RequestHandler):

  ranks = {
    -1: '-',
    0: 'Injected',
    1: '1',
    2: '2',
    3: '3',
    4: '4',
    5: '5',
  }

  def get(self):
    try:
      cert_id = int(self.request.get('id'))
    except (ValueError, TypeError):
      return self.error(404)

    self.show_cert(cert_id)

  def show_cert(self, cert_id):
    user = users.get_current_user()
    authkey = self.request.get('auth')

    try:
      cert = cert_data.get_cert_if_allowed(user, cert_id, authkey)
    except cert_data.CertNotFoundError:
      return self.error(404)
    except cert_data.PermissionDeniedError:
      return self.error(403)

    if user:
      characters = user_data.get_characters_for_user(user)
    else:
      characters = []

    skill_tree, skill_names = skill_data.get_skill_data()

    skills = []
    for skill in cert.required_skills:
      skills.append({
        'name': skill_names[skill.skill_id],
        'rank': skill.level,
        'id': skill.skill_id,
      })

    sharelink = "http://%s.appspot.com/cert?id=%d" % (
      app_identity.get_application_id(), cert.key().id())
    if not cert.public:
      sharelink += "&auth=%s" % cert.authkey

    data = {
      'cert': cert,
      'sharelink': sharelink,
      'owner': cert.owner == user,
      'characters': characters,
      'skills': skills,
    }

    char_id = self.request.get('character')
    if char_id:
      char_id = int(char_id)
      self.add_cert_progress(data, char_id, cert, characters)

    template = jinja_environment.get_template("view_cert.html")
    page = template.render(data)
    self.response.out.write(page)

  def add_cert_progress(self, data, char_id, cert, characters):
    character = user_data.find_character_by_id(char_id, characters)
    if character is None:
      return self.redirect("/cert?id=%d" % cert.key().id())

    charsheet = user_data.get_character_sheet(character)

    totals = {
      'overall': 0,
      'green': 0,
      'yellow': 0,
      'red': 0,
    }

    skill_progress = cert_data.get_cert_progress_dict(charsheet, cert)

    for skill in data['skills']:
      totals['overall'] += 1
      trained_rank, progress = skill_progress[skill['id']]
      skill['trained_rank'] = trained_rank
      skill['display_rank'] = self.ranks[trained_rank]
      if progress is cert_data.SKILL_SUFFICIENT:
        skill['row_class'] = 'success'
        totals['green'] += 1
      elif progress is cert_data.SKILL_INSUFFICIENT:
        skill['row_class'] = 'warning'
        totals['yellow'] += 1
      else:  # SKILL_UNTRAINED, SKILL_MISSING
        skill['row_class'] = 'error'
        totals['red'] += 1

    data['active_character'] = character

    if totals['overall']:
      percents = {
        'green': 100 * totals['green'] / totals['overall'],
        'yellow': 100 * totals['yellow'] / totals['overall'],
      }
      data['percents'] = percents

application = webapp2.WSGIApplication(
  [
    ('/apikeys', APIKeysHandler),
    ('/certs', CertificationsHandler),
    ('/browse', PublicCertificationsHandler),
    ('/skilltree', SkillTreeHandler),
    ('/cert', CertificationHandler),
    ('/', HomeHandler),
  ],
  debug=os.environ.get('SERVER_SOFTWARE', '').startswith('Dev'),
)
