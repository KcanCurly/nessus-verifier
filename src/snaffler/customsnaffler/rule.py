
from typing import List, Dict, Tuple
import toml
import re
from src.snaffler.customsnaffler.constants import EnumerationScope, MatchAction, MatchLoc, MatchListType, Triage

class SnaffleRule:
	def __init__(self, scope, id, name, action, category, relay, description, matchLocation, wordListType, matchLength, wordList, triage, importance, dontignorecase, notwordList) -> None:
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
		self.importance:str = importance
		self.dontignorecase:bool = dontignorecase
		self.notWordList:List[re.Pattern] = notwordList
		self.__convert_wordlist()

	def __convert_wordlist(self):
		#convert wordlist to regex
		res = []
		for word in self.wordList:
			if self.wordListType == MatchListType.Regex:
				pass
			elif self.wordListType == MatchListType.EndsWith:
				word = word + '$'
			elif self.wordListType == MatchListType.StartsWith:
				word = '^' + word
			elif self.wordListType == MatchListType.Contains:
				word = '.*' + word + '.*'
			elif self.wordListType == MatchListType.Exact:
				word = '^' + word + '$'

			if self.dontignorecase: res.append(re.compile(word, flags=re.MULTILINE))
			else: res.append(re.compile(word, flags=re.IGNORECASE|re.MULTILINE))
		self.wordList = res
  
		res = []
		for word in self.notWordList:
			if self.wordListType == MatchListType.Regex:
				pass
			elif self.wordListType == MatchListType.EndsWith:
				word = word + '$'
			elif self.wordListType == MatchListType.StartsWith:
				word = '^' + word
			elif self.wordListType == MatchListType.Contains:
				word = '.*' + word + '.*'
			elif self.wordListType == MatchListType.Exact:
				word = '^' + word + '$'

			if self.dontignorecase: res.append(re.compile(word, flags=re.MULTILINE))
			else: res.append(re.compile(word, flags=re.IGNORECASE|re.MULTILINE))
		self.notWordList = res

	
	def match(self, data):
		for rex in self.wordList:
			if not rex.search(data): continue
			for notrex in self.notWordList:
				if notrex.search(data): continue
			return True
		return False

	def determine_action(self, data):
		if self.match(data): return self.matchAction, self.triage
		return None, None
	
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
			'triage' : self.triage.value,
			'importance' : self.importance,
			'notWordList' : self.notWordList
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
			importance = d.get('importance', "0⭐")
			dontignorecase = d.get('dontignorecase', False)
			triage = Triage(d.get('triage', 'gray'))
			notWordList = d.get('notWordList', [])	
			if enumerationScope == EnumerationScope.File:
				obj = SnafflerFileRule
			elif enumerationScope == EnumerationScope.Directory:
				obj = SnafflerDirectoryRule
			elif enumerationScope == EnumerationScope.Content:
				obj = SnafflerContentsEnumerationRule
			else:
				raise NotImplementedError(f'EnumerationScope {enumerationScope} not implemented.')

			results.append(obj(enumerationScope, id, ruleName, matchAction, category, relayTargets, description, matchLocation, wordListType, matchLength, wordList, triage, importance, dontignorecase, notWordList))
		return results

