import random
from typing import Dict, List


class BotResponses:
    """Configurable response system for the ChatBot"""
    
    def __init__(self):
        # Predefined responses for general conversation
        self.general_responses = [
            "Hello! I'm a friendly chat bot. How can I help you today?",
            "That's interesting! Tell me more about that.",
            "I understand. Is there anything else you'd like to discuss?",
            "Thanks for chatting with me! I'm always here if you need someone to talk to.",
            "That sounds great! I hope everything works out well for you.",
            "I see what you mean. Have you considered trying a different approach?",
            "That's a good question! What do you think would be the best solution?",
            "I appreciate you sharing that with me. How are you feeling about it?",
            "Interesting perspective! I hadn't thought about it that way.",
            "That reminds me of something similar I've heard before. What happened next?",
            "I'm here to listen if you want to talk more about anything.",
            "That's wonderful! Congratulations on that achievement!",
            "I hope you have a great day! Feel free to message me anytime.",
            "Thanks for the conversation! I enjoyed chatting with you.",
            "That's quite an experience! How did that make you feel?"
        ]
        
        # Greeting messages for new conversations
        self.greetings = [
            "Hi there! I'm ChatBot, your friendly AI companion. What's on your mind today?",
            "Hello! Nice to meet you! I'm always here for a chat. How are you doing?",
            "Hey! Thanks for starting a conversation with me. What would you like to talk about?",
            "Hi! I'm ChatBot, and I'm here to chat whenever you need. What's up?",
        ]
        
        # Keyword-based response mappings
        self.keyword_responses = {
            'greetings': {
                'keywords': ['hello', 'hi', 'hey', 'greetings'],
                'response': "Hello! It's great to hear from you again! How are you doing?"
            },
            'farewells': {
                'keywords': ['bye', 'goodbye', 'see you', 'farewell'],
                'response': "Goodbye! It was lovely chatting with you. Take care and feel free to message me anytime!"
            },
            'thanks': {
                'keywords': ['thank', 'thanks', 'thx'],
                'response': "You're very welcome! I'm happy I could help. Is there anything else you'd like to talk about?"
            },
            'help': {
                'keywords': ['help', 'assistance', 'support'],
                'response': "I'd be happy to help! While I'm just a chat bot, I'm here to listen and chat with you. What's on your mind?"
            },
            'wellbeing': {
                'keywords': ['how are you', 'how do you feel', 'what\'s up'],
                'response': "I'm doing great, thank you for asking! I'm always excited to have new conversations. How about you?"
            },
            'negative_emotions': {
                'keywords': ['sad', 'upset', 'frustrated', 'angry', 'depressed'],
                'response': "I'm sorry to hear you're feeling that way. Sometimes it helps to talk about what's bothering you. I'm here to listen."
            },
            'positive_emotions': {
                'keywords': ['happy', 'excited', 'great', 'awesome', 'wonderful'],
                'response': "That's wonderful to hear! I love when people share positive news. What's making you so happy?"
            }
        }
        
        # Response for questions (contains '?')
        self.question_response = "That's a great question! I wish I had all the answers, but I'd love to hear your thoughts on it."
    
    def get_greeting(self) -> str:
        """Return a random greeting for new conversations"""
        return random.choice(self.greetings)
    
    def get_general_response(self) -> str:
        """Return a random general response"""
        return random.choice(self.general_responses)
    
    def analyze_message(self, message: str) -> str:
        """Analyze message and return appropriate response"""
        message_lower = message.lower()
        
        # Check keyword-based responses
        for category, config in self.keyword_responses.items():
            if any(keyword in message_lower for keyword in config['keywords']):
                return config['response']
        
        # Check if it's a question
        if '?' in message:
            return self.question_response
        
        # Default to general response
        return self.get_general_response()
    
    def get_response(self, user: str, message: str, active_conversations: Dict[str, List[str]]) -> str:
        """
        Generate a response based on the user and their message
        
        Args:
            user: Username of the person sending the message
            message: The message content
            active_conversations: Dictionary tracking conversation history
            
        Returns:
            Appropriate response string
        """
        # If this is the first message from this user, use a greeting
        if user not in active_conversations:
            active_conversations[user] = []
            return self.get_greeting()
        
        # Add the user's message to conversation history
        active_conversations[user].append(f"{user}: {message}")
        
        # Analyze message and return appropriate response
        return self.analyze_message(message)
    
    def customize_responses(self, 
                          greetings: List[str] = None,
                          general_responses: List[str] = None,
                          keyword_responses: Dict = None):
        """
        Allow customization of bot responses
        
        Args:
            greetings: Custom greeting messages
            general_responses: Custom general responses  
            keyword_responses: Custom keyword-based responses
        """
        if greetings:
            self.greetings = greetings
        if general_responses:
            self.general_responses = general_responses
        if keyword_responses:
            self.keyword_responses.update(keyword_responses) 