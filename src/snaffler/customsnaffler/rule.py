
from typing import List, Dict, Tuple
import toml
import re
from src.snaffler.customsnaffler.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage

class SnaffleRule:
	def __init__(self, scope, id, name, action, category, relay, description, matchLocation, wordListType, matchLength, wordList, triage) -> None:
		self.scope:EnumerationScope = scope
		self.id:str = id
		self.name:str = name
		self.action:MatchAction = action
		self.category:list[str] = category
		self.relay:list[str] = relay
		self.description:str = description
		self.matchLocation:MatchLoc = matchLocation
		self.wordListType:MatchListType = wordListType
		self.matchLength:int = matchLength
		self.wordList:List[re.Pattern] = wordList
		self.triage:Triage = triage
		self.__convert_wordlist()

	def __convert_wordlist(self):
		#convert wordlist to regex
		res = []
		for word in self.wordList:
			if self.wordListType == MatchListType.Regex:
				a=1
			elif self.wordListType == MatchListType.EndsWith:
				word = word + '$'
			elif self.wordListType == MatchListType.StartsWith:
				word = '^' + word
			elif self.wordListType == MatchListType.Contains:
				word = '.*' + word + '.*'
			elif self.wordListType == MatchListType.Exact:
				word = '^' + word + '$'

			res.append(re.compile(word, flags=re.IGNORECASE))
		self.wordList = res

	
	def match(self, data):
		for rex in self.wordList:
			if rex.search(data) is not None:
				return True
		return False

	def determine_action(self, data):
		print("a")
		if self.match(data) is False:
			return None, None
		return self.matchAction, self.triage
	
	def __repr__(self):
		return str(self.to_toml())
	
	def to_toml(self):
		return toml.dumps(self.to_dict())

	def to_dict(self):
		return {
			'scope' : self.scope.value,
			'id' : self.id,	
			'name' : self.name,
			'action' : self.action.value,
			'category' : self.category,
			'relay' : self.relay,
			'description' : self.description,
			'matchLocation' : self.matchLocation.value,
			'wordListType' : self.wordListType.value,
			'matchLength' : self.matchLength,
			'wordList' : self.wordList,
			'triage' : self.triage.value
		}
	
	@staticmethod
	def from_dict(datadict:Dict):
		from src.snaffler.customsnaffler.file import SnafflerFileRule
		from src.snaffler.customsnaffler.directory import SnafflerDirectoryRule
		from src.snaffler.customsnaffler.contents import SnafflerContentsEnumerationRule
		
		results = []
		if 'Rule' not in datadict:
			return []
		for d in datadict['Rule']:
			enumerationScope = EnumerationScope(d['scope'])
			id = d.get('id', "d0")
			ruleName = d.get('name', 'Unnamed Rule')
			matchAction = MatchAction(d['action'])
			category = d.get('category', [])
			relayTargets = d.get('relay', []) 
			description = d.get('description', 'No description')
			matchLocation = MatchLoc(d['matchLocation'])
			wordListType = MatchListType(d['wordListType'])
			matchLength = d.get('matchLength', 0)
			wordList = d.get('wordList', [])
			triage = Triage(d.get('triage', 'Gray'))
			if enumerationScope == EnumerationScope.File:
				obj = SnafflerFileRule
			elif enumerationScope == EnumerationScope.Directory:
				obj = SnafflerDirectoryRule
			elif enumerationScope == EnumerationScope.Content:
				obj = SnafflerContentsEnumerationRule
			else:
				raise NotImplementedError(f'EnumerationScope {enumerationScope} not implemented.')

			results.append(obj(enumerationScope, id, ruleName, matchAction, category, relayTargets, description, matchLocation, wordListType, matchLength, wordList, triage))
		return results

