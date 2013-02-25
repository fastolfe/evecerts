import random
import string

from google.appengine.api import memcache

import models
import skill_data


def random_string(N):
  choices = string.ascii_letters + string.digits
  return ''.join(random.choice(choices) for _ in range(N))


def get_public_certs(offset=0, limit=None):
  """Returns an iterable of dicts describing all public certificates."""
  query = models.Certification.all().filter("public =", True)
  query = query.order('-modified')
  return certs_to_dicts(query.run(offset=offset, limit=limit))


def get_certs_for_owner(user, offset=0, limit=None):
  """Returns an iterable of dicts for all certificates owned by this user."""
  query = models.Certification.all().filter("owner =", user)
  return certs_to_dicts(query.run(offset=offset, limit=limit))


def certs_to_dicts(certs):
  for cert in certs:
    yield {
        'id': cert.key().id(),
        'name': cert.name,
        'owner': cert.owner,
        'authkey': cert.authkey,
        'public': cert.public,
        'modified': cert.modified.strftime("%x %X"),
        'skills': cert.required_skills.count(),
    }


class CertError(Exception):
  pass

class CertNameInvalid(CertError):
  pass

class PermissionDeniedError(CertError):
  pass

class CertNotFoundError(CertError):
  pass


def create_cert(user, name):
  if not (3 < len(name) < 101):
    raise CertNameInvalid("Name must be between 4 and 100 characters.")

  cert = models.Certification(name=name, owner=user)
  cert.put()
  return cert


def remove_cert(cert_id):
  cert = models.Certification.get_by_id(cert_id)
  if cert:
    cert.delete()
    return True
  return False


def get_cert_if_owner(owner, cert_id):
  cert = models.Certification.get_by_id(cert_id)
  if not cert:
    raise CertNotFoundError('No such certificate ID: %r' % cert_id)
  if cert.owner != owner:
    raise PermissionDeniedError()

  return cert


def get_cert_if_allowed(user, cert_id, auth_key):
  cert = models.Certification.get_by_id(cert_id)
  if not cert:
    raise CertNotFoundError('No such certificate ID: %r' % cert_id)

  if cert.public or cert.owner == user:
    return cert

  if auth_key and auth_key == cert.authkey:
    return cert

  raise PermissionDeniedError()


CERT_SKILLS_CACHE_KEY_FORMAT = "cert-skills-1-%s"


def get_cert_skills_dict(cert, skill_names):
  cert_id = cert.key().id()
  mc_key = CERT_SKILLS_CACHE_KEY_FORMAT % cert_id
  skills = memcache.get(mc_key)
  if not skills:
    skills = []
    for skill in cert.required_skills:
      skills.append({
        'name': skill_names[skill.skill_id],
        'rank': skill.level,
        'id': skill.skill_id,
      })
    memcache.set(mc_key, skills)
  return skills


class SkillNotFoundError(CertError):
  pass


class InvalidRankError(CertError):
  pass


def add_skill(owner, cert_id, skill_id, rank):
  cert = get_cert_if_owner(owner, cert_id)

  skill_tree, skill_names = skill_data.get_skill_data()
  if skill_id not in skill_names:
    raise SkillNotFoundError('%r is not a known skill' % skill_id)

  if not (0 < rank < 6):
    raise InvalidRankError('%r is not a valid skill rank' % rank)

  for required_skill in cert.required_skills:
    if required_skill.skill_id == skill_id:
      if required_skill.level < rank:
        required_skill.level = rank
        required_skill.put()
      break
  else:
    required_skill = models.RequiredSkill(
      skill_id=skill_id, level=rank, cert=cert)
    required_skill.put()

  memcache.delete(CERT_SKILLS_CACHE_KEY_FORMAT % cert_id)


def remove_skill(owner, cert_id, skill_id):
  cert = get_cert_if_owner(owner, cert_id)

  for skill in cert.required_skills:
    if skill.skill_id == skill_id:
      skill.delete()
      break

  memcache.delete(CERT_SKILLS_CACHE_KEY_FORMAT % cert_id)

def toggle_lock(owner, cert_id):
  cert = get_cert_if_owner(owner, cert_id)

  if cert.public:
    cert.public = False
    if not cert.authkey:
      cert.authkey = random_string(8)
  else:
    cert.public = True

  cert.put()


def reset_link(owner, cert_id):
  cert = get_cert_if_owner(owner, cert_id)

  cert.authkey = random_string(8)
  cert.put()


SKILL_MISSING = 0
SKILL_UNTRAINED = 1
SKILL_INSUFFICIENT = 2
SKILL_SUFFICIENT = 3


def get_cert_progress(charsheet, cert):
  skill_to_rank = {}
  for skill in charsheet['skills']:
    skill_to_rank[skill['id']] = skill['level']

  skill_tree, skill_names = skill_data.get_skill_data()

  for skill in cert.required_skills:
    trained_rank = skill_to_rank.get(skill.skill_id, -1)
    if trained_rank >= skill.level:
      yield skill, trained_rank, SKILL_SUFFICIENT
    elif trained_rank > 0:
      yield skill, trained_rank, SKILL_INSUFFICIENT
    elif trained_rank == 0:
      yield skill, trained_rank, SKILL_UNTRAINED
    else:
      yield skill, trained_rank, SKILL_MISSING


def get_cert_progress_dict(charsheet, cert):
  progress_dict = {}

  for skill, rank, progress in get_cert_progress(charsheet, cert):
    progress_dict[skill.skill_id] = (rank, progress)

  return progress_dict
