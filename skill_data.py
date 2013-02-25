import json

from google.appengine.api import memcache

import evelink
from evelink import appengine as elink_appengine
import models

class SkillTreeError(Exception):
  pass

SKILL_TREE_CACHE_KEY = 'skill-tree-1'
SKILL_NAMES_CACHE_KEY = 'skill-names-1'
SKILL_GROUPS_CACHE_KEY = 'skill-groups'


def refresh_skill_tree():
  """Refreshes skill tree and caches results internally.

  Returns the refreshed skill data (a la get_skill_data).
  """
  skilltree = models.SkillTree.all().get()

  try:
    elink_api = elink_appengine.AppEngineAPI(deadline=20)
    elink_eve = evelink.eve.EVE(api=elink_api)
    treedata = elink_eve.skill_tree()
  except evelink.api.APIError as e:
    raise SkillTreeError(e)

  _cache_skill_data(treedata)

  if skilltree:
    skilltree.json_data = json.dumps(treedata)
  else:
    skilltree = models.SkillTree(json_data = json.dumps(treedata))
  skilltree.put()

  return treedata


def _cache_skill_data(treedata):
  memcache.set(SKILL_TREE_CACHE_KEY, treedata)
  memcache.delete(SKILL_GROUPS_CACHE_KEY)
  get_skill_data()


def get_skill_data():
  """Retrieves the skill tree data.

  Returns:
    (tree of skills, dict of skill IDs to names)
  """
  treedata = memcache.get(SKILL_TREE_CACHE_KEY)
  if not treedata:
    skilltree = models.SkillTree.all().get()
    treedata = json.loads(skilltree.json_data)
    memcache.set(SKILL_TREE_CACHE_KEY, treedata)

  skill_names = memcache.get(SKILL_NAMES_CACHE_KEY)
  if not skill_names:
    skill_names = {}
    for skillgroup in treedata.itervalues():
      for skill in skillgroup['skills'].itervalues():
        skill_names[skill['id']] = skill['name']
    memcache.set(SKILL_NAMES_CACHE_KEY, skill_names)

  return treedata, skill_names


def get_skill_groups(skill_tree):
  """Retrieves the skill tree, as a dict keyed on group name."""
  skillgroups = memcache.get(SKILL_GROUPS_CACHE_KEY)
  if not skillgroups:
    skillgroups = []
    for group in skill_tree.itervalues():
      s = [s for s in group['skills'].itervalues() if s['published']]
      if not s:
        continue
      skillgroup = {
        'name': group['name'],
        'skills': sorted(s, key=lambda x: x['name'])
      }
      skillgroups.append(skillgroup)
    skillgroups.sort(key=lambda x: x['name'])
    memcache.set(SKILL_GROUPS_CACHE_KEY, skillgroups)
  return skillgroups
