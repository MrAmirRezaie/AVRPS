#!/usr/bin/env python3
"""
AVRPS Intelligent Chatbot with NLP and Language Models
Advanced Natural Language Interface for AVRPS

Features:
- Transformer-based intent classification (BERT)
- spaCy NLP for entity recognition and linguistic analysis
- Semantic similarity matching
- Confidence scoring and validation
- Multi-turn conversation support
- Request validation against AVRPS capabilities
"""

import os
import sys
import json
import argparse
import subprocess
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime
from pathlib import Path
import warnings

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IntentType(Enum):
    """AVRPS Operations - Intent Types"""
    SCAN = "scan"
    REMEDIATE = "remediate"
    DRY_RUN = "dry_run"
    REPORT = "report"
    CLEANUP = "cleanup"
    SYNC_CVE = "sync_cve"
    NETWORK_ANALYSIS = "network_analysis"
    HELP = "help"
    VERSION = "version"
    CONFIGURE = "configure"
    UNKNOWN = "unknown"


@dataclass
class Intent:
    """Represents a recognized intent"""
    type: IntentType
    confidence: float
    entities: Dict[str, Any] = field(default_factory=dict)
    modifiers: Dict[str, bool] = field(default_factory=dict)
    reasoning: str = ""
    raw_input: str = ""


class NLPEngine:
    """NLP Engine using spaCy and transformers"""
    
    def __init__(self):
        """Initialize NLP components"""
        self.nlp_loaded = False
        self.bert_loaded = False
        self.nlp = None
        self.classifier = None
        
        try:
            import spacy
            try:
                self.nlp = spacy.load("en_core_web_sm")
                self.nlp_loaded = True
                logger.info("✓ spaCy NLP model loaded successfully")
            except OSError:
                logger.warning("⚠ spaCy model not found. Install with: python -m spacy download en_core_web_sm")
                self.nlp = None
        except ImportError:
            logger.warning("⚠ spaCy not installed. Install with: pip install spacy")
            self.nlp = None
        
        try:
            from transformers import pipeline
            self.classifier = pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli",
                device=-1  # Use CPU, set to 0 for GPU
            )
            self.bert_loaded = True
            logger.info("✓ Transformer model (BART-large-MNLI) loaded successfully")
        except ImportError:
            logger.warning("⚠ Transformers not installed. Install with: pip install transformers torch")
            self.classifier = None
        except Exception as e:
            logger.warning(f"⚠ Could not load transformer model: {e}. Using keyword-based matching only.")
            self.classifier = None
    
    def tokenize(self, text: str) -> List[str]:
        """Tokenize text"""
        if self.nlp:
            doc = self.nlp(text)
            return [token.text for token in doc]
        return text.lower().split()
    
    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract named entities from text"""
        entities = {}
        if self.nlp:
            doc = self.nlp(text)
            for ent in doc.ents:
                if ent.label_ not in entities:
                    entities[ent.label_] = []
                entities[ent.label_].append(ent.text)
        return entities
    
    def classify_intent(self, text: str, candidate_labels: List[str]) -> Tuple[str, float]:
        """Classify intent using zero-shot classification"""
        if self.classifier:
            try:
                result = self.classifier(text, candidate_labels, multi_class=True)
                return result['labels'][0], result['scores'][0]
            except Exception as e:
                logger.warning(f"Classification error: {e}")
        return "unknown", 0.0
    
    def get_dependency_tree(self, text: str) -> List[Tuple[str, str, str]]:
        """Extract dependency tree from text"""
        if self.nlp:
            doc = self.nlp(text)
            return [(token.text, token.dep_, token.head.text) for token in doc]
        return []


class IntentRecognizer:
    """Recognizes user intent using NLP and ML models"""
    
    def __init__(self, nlp_engine: NLPEngine):
        """Initialize intent recognizer"""
        self.nlp = nlp_engine
        
        # Intent definitions with keywords and descriptions
        self.intents = {
            IntentType.SCAN: {
                "description": "Scan system for vulnerabilities",
                "keywords": ["scan", "check", "detect", "find", "analyze", "assess", "vulnerabilities", "cves", "security issues"],
                "examples": [
                    "scan my system",
                    "check for vulnerabilities",
                    "detect security issues"
                ]
            },
            IntentType.REMEDIATE: {
                "description": "Apply patches and fix vulnerabilities",
                "keywords": ["fix", "patch", "remediate", "apply", "resolve", "repair", "update", "upgrade"],
                "examples": [
                    "fix vulnerabilities",
                    "apply patches",
                    "remediate issues"
                ]
            },
            IntentType.DRY_RUN: {
                "description": "Preview operations without changes",
                "keywords": ["dry run", "test", "preview", "simulate", "what if", "trial", "without changes"],
                "examples": [
                    "test the remediation",
                    "preview patches",
                    "dry run without making changes"
                ]
            },
            IntentType.REPORT: {
                "description": "Generate security reports",
                "keywords": ["report", "generate", "export", "save", "display", "show results"],
                "examples": [
                    "generate a report",
                    "export results",
                    "create a report"
                ]
            },
            IntentType.CLEANUP: {
                "description": "Manage and clean up data",
                "keywords": ["cleanup", "clean", "delete", "remove", "clear", "retention", "maintenance"],
                "examples": [
                    "clean up old data",
                    "remove old files",
                    "maintenance cleanup"
                ]
            },
            IntentType.SYNC_CVE: {
                "description": "Synchronize CVE database",
                "keywords": ["sync", "synchronize", "update", "fetch", "download", "refresh", "cve database"],
                "examples": [
                    "sync CVE database",
                    "update vulnerability data",
                    "fetch latest CVEs"
                ]
            },
            IntentType.NETWORK_ANALYSIS: {
                "description": "Analyze network vulnerabilities",
                "keywords": ["network", "graph", "analyze network", "relationship", "connections"],
                "examples": [
                    "analyze network vulnerabilities",
                    "generate network graph",
                    "network analysis"
                ]
            },
            IntentType.HELP: {
                "description": "Get help information",
                "keywords": ["help", "how", "usage", "guide", "tutorial", "capabilities"],
                "examples": [
                    "help me",
                    "how to use",
                    "show capabilities"
                ]
            },
            IntentType.VERSION: {
                "description": "Show version information",
                "keywords": ["version", "about", "info", "information"],
                "examples": [
                    "what is your version",
                    "about AVRPS",
                    "show info"
                ]
            },
            IntentType.CONFIGURE: {
                "description": "Configure AVRPS settings",
                "keywords": ["configure", "config", "settings", "setup", "preferences", "options", "manage cve"],
                "examples": [
                    "configure AVRPS",
                    "update settings",
                    "manage CVE databases"
                ]
            },
            IntentType.UNKNOWN: {
                "description": "Unknown intent",
                "keywords": [],
                "examples": []
            }
        }
    
    def recognize(self, user_input: str) -> Intent:
        """
        Recognize intent from user input using NLP
        
        Args:
            user_input: Natural language user input
            
        Returns:
            Intent object with recognized intent and confidence
        """
        user_input_lower = user_input.lower().strip()
        
        # Get intent labels and descriptions
        intent_labels = [intent.value for intent in IntentType if intent != IntentType.UNKNOWN]
        intent_descriptions = [self.intents[intent]["description"] for intent in IntentType if intent != IntentType.UNKNOWN]
        
        # Method 1: Keyword matching (baseline)
        keyword_scores = {}
        for intent_type in IntentType:
            if intent_type == IntentType.UNKNOWN:
                continue
            keywords = self.intents[intent_type]["keywords"]
            matches = sum(1 for kw in keywords if kw in user_input_lower)
            keyword_scores[intent_type] = matches / len(keywords) if keywords else 0
        
        best_keyword_intent = max(keyword_scores, key=keyword_scores.get)
        keyword_confidence = keyword_scores[best_keyword_intent]
        
        # Method 2: Transformer-based classification (if available)
        if self.nlp.classifier:
            try:
                predicted_intent, bert_confidence = self.nlp.classify_intent(
                    user_input,
                    intent_descriptions
                )
                bert_intent = IntentType(predicted_intent.lower())
                
                # Combine both methods
                final_intent = best_keyword_intent if keyword_confidence > 0 else bert_intent
                final_confidence = (keyword_confidence + bert_confidence) / 2
                
                reasoning = f"Keyword match: {best_keyword_intent.value} ({keyword_confidence:.2f}), BERT: {predicted_intent} ({bert_confidence:.2f})"
            except Exception as e:
                final_intent = best_keyword_intent if keyword_confidence > 0 else IntentType.UNKNOWN
                final_confidence = keyword_confidence
                reasoning = f"Keyword matching: {best_keyword_intent.value} ({keyword_confidence:.2f})"
        else:
            final_intent = best_keyword_intent if keyword_confidence > 0 else IntentType.UNKNOWN
            final_confidence = keyword_confidence
            reasoning = f"Keyword matching: {best_keyword_intent.value} ({keyword_confidence:.2f})"
        
        # Extract modifiers
        modifiers = self._extract_modifiers(user_input_lower)
        
        # Extract entities
        entities = self.nlp.extract_entities(user_input)
        
        intent = Intent(
            type=final_intent,
            confidence=final_confidence,
            entities=entities,
            modifiers=modifiers,
            reasoning=reasoning,
            raw_input=user_input
        )
        
        return intent
    
    def _extract_modifiers(self, text: str) -> Dict[str, bool]:
        """Extract operation modifiers from text"""
        modifiers = {
            "report": any(kw in text for kw in ["report", "generate report", "export"]),
            "force": any(kw in text for kw in ["force", "without confirmation", "don't ask"]),
            "verbose": any(kw in text for kw in ["verbose", "detailed", "details", "verbose output"]),
            "quiet": any(kw in text for kw in ["quiet", "silent", "suppress", "no output"]),
            "deep_scan": any(kw in text for kw in ["deep", "thorough", "comprehensive", "in-depth"]),
        }
        return modifiers


class CommandValidator:
    """Validates requests against AVRPS capabilities"""
    
    def __init__(self):
        """Initialize validator with AVRPS capabilities"""
        self.allowed_intents = {
            IntentType.SCAN,
            IntentType.REMEDIATE,
            IntentType.DRY_RUN,
            IntentType.REPORT,
            IntentType.CLEANUP,
            IntentType.SYNC_CVE,
            IntentType.NETWORK_ANALYSIS,
            IntentType.HELP,
            IntentType.VERSION,
        }
        
        # Modifier compatibility
        self.modifier_compatibility = {
            IntentType.SCAN: {"report", "verbose", "quiet", "deep_scan"},
            IntentType.REMEDIATE: {"report", "force", "verbose", "quiet"},
            IntentType.DRY_RUN: {"verbose", "quiet"},
            IntentType.CLEANUP: {"verbose", "quiet"},
            IntentType.SYNC_CVE: {"verbose", "quiet"},
            IntentType.NETWORK_ANALYSIS: {"verbose", "quiet"},
        }
        
        # Conflicting modifiers
        self.conflicts = [
            ({"verbose"}, {"quiet"})
        ]
    
    def validate(self, intent: Intent) -> Tuple[bool, str]:
        """
        Validate intent against AVRPS capabilities
        
        Args:
            intent: Intent to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if intent is supported
        if intent.type == IntentType.UNKNOWN:
            return False, "I couldn't understand your request. Could you rephrase it?"
        
        if intent.type not in self.allowed_intents:
            return False, f"The '{intent.type.value}' operation is not available."
        
        # Check modifier compatibility
        enabled_modifiers = {mod for mod, enabled in intent.modifiers.items() if enabled}
        allowed_mods = self.modifier_compatibility.get(intent.type, set())
        
        incompatible = enabled_modifiers - allowed_mods
        if incompatible:
            return False, f"Modifiers {incompatible} are not compatible with {intent.type.value}."
        
        # Check for conflicting modifiers
        for conflict_set1, conflict_set2 in self.conflicts:
            if conflict_set1 & enabled_modifiers and conflict_set2 & enabled_modifiers:
                return False, f"Conflicting modifiers: {conflict_set1} and {conflict_set2}"
        
        # Check confidence threshold
        if intent.confidence < 0.15:
            return False, "I'm not confident about what you're asking. Could you be more specific?"
        
        return True, ""


class CommandBuilder:
    """Builds AVRPS CLI commands from validated intents"""
    
    @staticmethod
    def build(intent: Intent) -> List[str]:
        """
        Build AVRPS command line arguments
        
        Args:
            intent: Validated Intent object
            
        Returns:
            List of command line arguments
        """
        cmd = [sys.executable, "AVRPS.py"]
        
        # Map intent to AVRPS flag
        intent_flags = {
            IntentType.SCAN: "--scan",
            IntentType.REMEDIATE: "--remediate",
            IntentType.DRY_RUN: "--dry-run",
            IntentType.CLEANUP: "--cleanup",
            IntentType.SYNC_CVE: "--sync-cves",
            IntentType.NETWORK_ANALYSIS: "--network-analysis",
        }
        
        if intent.type in intent_flags:
            cmd.append(intent_flags[intent.type])
        
        # Add enabled modifiers
        if intent.modifiers.get("report"):
            cmd.append("--report")
        if intent.modifiers.get("force"):
            cmd.append("--force")
        if intent.modifiers.get("verbose"):
            cmd.append("--verbose")
        if intent.modifiers.get("quiet"):
            cmd.append("--quiet")
        if intent.modifiers.get("deep_scan"):
            cmd.append("--deep-scan")
        
        return cmd


class ResponseGenerator:
    """Generates natural language responses"""
    
    @staticmethod
    def welcome() -> str:
        """Welcome message"""
        return """
╔════════════════════════════════════════════════════════════════╗
║          AVRPS Intelligent Chatbot with NLP Models             ║
║  Advanced Vulnerability Remediation and Patching System        ║
╚════════════════════════════════════════════════════════════════╝

🤖 I'm an AI-powered chatbot for AVRPS, equipped with:
   • Natural Language Processing (spaCy)
   • Intent Classification (Transformers/BERT)
   • Entity Recognition
   • Semantic Understanding

I can help you:
  • Scan for vulnerabilities
  • Apply security patches
  • Generate reports
  • Manage CVE databases
  • Analyze network vulnerabilities
  • Perform maintenance

Just describe what you need in natural language!

Type 'help' for examples or 'quit' to exit.
        """
    
    @staticmethod
    def confirm_action(intent: Intent) -> str:
        """Generate confirmation message"""
        intent_messages = {
            IntentType.SCAN: "I'll scan your system for vulnerabilities",
            IntentType.REMEDIATE: "I'll scan and apply patches for vulnerabilities",
            IntentType.DRY_RUN: "I'll perform a test run to preview remediation",
            IntentType.CLEANUP: "I'll clean up old data from the system",
            IntentType.SYNC_CVE: "I'll synchronize the CVE database",
            IntentType.NETWORK_ANALYSIS: "I'll analyze network vulnerabilities",
        }
        
        msg = intent_messages.get(intent.type, "I'll help you")
        
        # Add modifiers
        modifiers = []
        if intent.modifiers.get("deep_scan"):
            modifiers.append("using a deep scan")
        if intent.modifiers.get("report"):
            modifiers.append("and generate reports")
        if intent.modifiers.get("force"):
            modifiers.append("without confirmation")
        if intent.modifiers.get("verbose"):
            modifiers.append("with detailed output")
        
        if modifiers:
            msg += " " + " ".join(modifiers)
        
        msg += f".\n\n📊 Confidence: {intent.confidence:.1%}"
        msg += f"\n📝 Intent: {intent.type.value}"
        
        return msg
    
    @staticmethod
    def invalid_request(reason: str) -> str:
        """Generate invalid request message"""
        return f"""
❌ {reason}

Please rephrase your request. Examples:
  • "Scan my system for vulnerabilities"
  • "Apply security patches"
  • "Generate a report"
  • "Sync the CVE database"

Type 'help' for more examples.
        """
    
    @staticmethod
    def help_text() -> str:
        """Help text with examples"""
        return """
📚 AVRPS Chatbot Examples:

🔍 SCANNING
  "Scan my system for vulnerabilities"
  "Check for security issues"
  "Perform a deep scan"
  "Analyze my system in detail"

🔧 REMEDIATION
  "Fix vulnerabilities on my system"
  "Apply security patches"
  "Remediate all issues"
  "Update and patch my system"

🧪 TEST RUN
  "What patches would be applied?"
  "Test the remediation process"
  "Preview security updates"

📈 REPORTING
  "Scan and generate a report"
  "Create a vulnerability report"
  "Generate detailed report with results"

🔄 CVE DATABASE
  "Sync the CVE database"
  "Update vulnerability information"

🔗 NETWORK ANALYSIS
  "Analyze network vulnerabilities"
  "Generate a network graph"

🧹 MAINTENANCE
  "Clean up old data"
  "Remove old files"

💡 Tips:
  ✓ Use natural language - I understand many phrasings
  ✓ Combine operations - "Scan and generate a report"
  ✓ Add details - "Deep scan with verbose output"
        """


class AVRPSChatbot:
    """Main AI-powered chatbot for AVRPS"""
    
    def __init__(self, history_file: Optional[str] = None):
        """
        Initialize chatbot with NLP and ML models
        
        Args:
            history_file: Optional file path to save conversation history
        """
        logger.info("Initializing AVRPS Intelligent Chatbot...")
        self.nlp_engine = NLPEngine()
        self.intent_recognizer = IntentRecognizer(self.nlp_engine)
        self.validator = CommandValidator()
        self.command_builder = CommandBuilder()
        self.response_gen = ResponseGenerator()
        self.conversation_history: List[Dict] = []
        self.history_file = history_file
        self.session_start = datetime.now()
        logger.info("✓ Chatbot initialization complete")
        logger.info(f"  NLP Loaded: {self.nlp_engine.nlp_loaded}")
        logger.info(f"  BERT Loaded: {self.nlp_engine.bert_loaded}")
    
    def process_input(self, user_input: str) -> Tuple[bool, str]:
        """
        Process user input end-to-end
        
        Args:
            user_input: Natural language input from user
            
        Returns:
            Tuple of (success, response)
        """
        user_input = user_input.strip()
        if not user_input:
            return False, "Please enter a command."
        
        # Recognize intent using NLP
        logger.info(f"Processing user input: {user_input}")
        intent = self.intent_recognizer.recognize(user_input)
        logger.info(f"Recognized intent: {intent.type.value} (confidence: {intent.confidence:.2f})")
        logger.info(f"Reasoning: {intent.reasoning}")
        
        # Store in history
        self.conversation_history.append({
            "timestamp": datetime.now().isoformat(),
            "input": user_input,
            "intent": intent.type.value,
            "confidence": intent.confidence,
            "modifiers": intent.modifiers,
            "reasoning": intent.reasoning
        })
        
        # Handle special commands
        if intent.type == IntentType.HELP:
            return True, self.response_gen.help_text()
        
        if intent.type == IntentType.VERSION:
            return True, "AVRPS Version 3.0.0\nAuthor: MrAmirRezaie\nWith Intelligent NLP Chatbot"
        
        # Validate intent
        is_valid, error_msg = self.validator.validate(intent)
        if not is_valid:
            return False, self.response_gen.invalid_request(error_msg)
        
        # Generate confirmation
        confirmation = self.response_gen.confirm_action(intent)
        print(confirmation)
        
        # Ask for confirmation before executing remediation
        if intent.type == IntentType.REMEDIATE and not intent.modifiers.get("force"):
            response = input("\n⚠️  Proceed with remediation? (yes/no): ").strip().lower()
            if response not in ['yes', 'y']:
                return False, "Operation cancelled."
        
        # Build and execute command
        try:
            cmd = self.command_builder.build(intent)
            print(f"\n🚀 Executing: {' '.join(cmd)}\n")
            
            result = subprocess.run(
                cmd,
                cwd=os.path.dirname(os.path.abspath(__file__)),
                encoding='utf-8',
                errors='replace',
                capture_output=False
            )
            
            success = result.returncode == 0
            if success:
                return True, "\n✅ Operation completed successfully!"
            else:
                return False, f"\n❌ Operation failed with exit code {result.returncode}"
        
        except FileNotFoundError:
            return False, "❌ Error: AVRPS.py not found in current directory."
        except Exception as e:
            return False, f"❌ Error: {str(e)}"
    
    def save_history(self, filepath: Optional[str] = None) -> bool:
        """
        Save conversation history to file
        
        Args:
            filepath: Path to save history (uses self.history_file if not provided)
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            target_file = filepath or self.history_file
            if not target_file:
                return False
            
            with open(target_file, 'w') as f:
                json.dump({
                    "session_start": self.session_start.isoformat(),
                    "session_end": datetime.now().isoformat(),
                    "conversation_count": len(self.conversation_history),
                    "history": self.conversation_history
                }, f, indent=2)
            
            logger.info(f"✓ History saved to {target_file}")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to save history: {e}")
            return False
    
    def load_history(self, filepath: str) -> bool:
        """
        Load conversation history from file
        
        Args:
            filepath: Path to history file
            
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                self.conversation_history = data.get("history", [])
                logger.info(f"✓ History loaded from {filepath}")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to load history: {e}")
            return False
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get session statistics
        
        Returns:
            Dictionary with session statistics
        """
        if not self.conversation_history:
            return {"total_requests": 0}
        
        intents = {}
        avg_confidence = 0
        
        for entry in self.conversation_history:
            intent = entry.get("intent", "unknown")
            intents[intent] = intents.get(intent, 0) + 1
            avg_confidence += entry.get("confidence", 0)
        
        avg_confidence /= len(self.conversation_history) if self.conversation_history else 1
        
        return {
            "total_requests": len(self.conversation_history),
            "session_duration": str(datetime.now() - self.session_start),
            "intents": intents,
            "average_confidence": round(avg_confidence, 3),
            "nlp_available": self.nlp_engine.nlp_loaded,
            "bert_available": self.nlp_engine.bert_loaded
        }
    
    def run_interactive(self):
        """Run interactive chatbot session"""
        print(self.response_gen.welcome())
        
        while True:
            try:
                user_input = input("\n🤖 You: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    # Prompt to save history
                    if self.conversation_history:
                        save_prompt = input("\n💾 Save conversation history? (yes/no): ").strip().lower()
                        if save_prompt in ['yes', 'y']:
                            filename = f"chat_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                            if self.save_history(filename):
                                print(f"✓ History saved to {filename}")
                    
                    # Show session stats
                    stats = self.get_session_stats()
                    if stats.get("total_requests", 0) > 0:
                        print(f"\n📊 Session Summary:")
                        print(f"  - Total requests: {stats['total_requests']}")
                        print(f"  - Session duration: {stats['session_duration']}")
                        print(f"  - Average confidence: {stats['average_confidence']}")
                    
                    print("\n👋 Thank you for using AVRPS Chatbot. Goodbye!")
                    break
                
                if not user_input:
                    continue
                
                success, response = self.process_input(user_input)
                print(f"\n🤖 Assistant: {response}")
            
            except KeyboardInterrupt:
                print("\n\n👋 Interrupted. Goodbye!")
                break
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                print(f"\n❌ Unexpected error: {str(e)}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="AVRPS Intelligent Chatbot with NLP and Language Models",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python chatbot.py                  # Start interactive mode
  python chatbot.py --single "scan"  # Single command mode
  python chatbot.py --history        # Show conversation history
  python chatbot.py --stats          # Show session statistics
  python chatbot.py --verbose        # Enable debug logging
        """
    )
    
    parser.add_argument(
        "--single",
        type=str,
        help="Process a single command and exit"
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show conversation history"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show session statistics"
    )
    parser.add_argument(
        "--save-history",
        type=str,
        help="Save conversation history to file"
    )
    parser.add_argument(
        "--load-history",
        type=str,
        help="Load conversation history from file"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    chatbot = AVRPSChatbot(history_file=args.save_history)
    
    # Load history if requested
    if args.load_history:
        chatbot.load_history(args.load_history)
    
    if args.single:
        success, response = chatbot.process_input(args.single)
        print(response)
        if args.save_history:
            chatbot.save_history()
        sys.exit(0 if success else 1)
    
    if args.history:
        if chatbot.conversation_history:
            print("\n📋 Conversation History:")
            print(json.dumps(chatbot.conversation_history, indent=2))
        else:
            print("No history available.")
        return
    
    if args.stats:
        stats = chatbot.get_session_stats()
        print("\n📊 Session Statistics:")
        print(json.dumps(stats, indent=2))
        return
    
    # Start interactive chatbot
    try:
        chatbot.run_interactive()
    finally:
        # Save history on exit if requested
        if args.save_history:
            chatbot.save_history()

if __name__ == "__main__":
    main()