from common.celery_app import celery_app
from common.db import SessionLocal, Sample
from sqlalchemy import select
import yara
import os
import magic
import logging

logger = logging.getLogger(__name__)

# Default Yara rules for testing
DEFAULT_RULES = """
rule TestMalware {
    strings:
        $test1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $test2 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
        $malware1 = { 4D 5A } // MZ header
        $malware2 = "This program cannot be run in DOS mode"
    condition:
        $test1 or $test2 or (uint16(0) == 0x5A4D and $malware2)
}

rule SuspiciousStrings {
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase  
        $s3 = "rundll32" nocase
        $s4 = "regsvr32" nocase
        $s5 = "CreateRemoteThread" nocase
        $s6 = "WriteProcessMemory" nocase
    condition:
        any of them
}

rule PEFile {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}
"""

def get_compiled_rules():
    """Get compiled Yara rules"""
    rules_file = "/app/yara-rules/rules.yar"
    
    # Create default rules if they don't exist
    if not os.path.exists(rules_file):
        os.makedirs(os.path.dirname(rules_file), exist_ok=True)
        with open(rules_file, 'w') as f:
            f.write(DEFAULT_RULES)
    
    try:
        return yara.compile(filepath=rules_file)
    except Exception as e:
        logger.warning(f"Failed to compile rules file, using default: {e}")
        return yara.compile(source=DEFAULT_RULES)

@celery_app.task(name='yara.scan_file')
def scan_file(sha256: str, file_content: bytes = None):
    """
    Scan a file using Yara rules
    """
    logger.info(f"Starting Yara scan for file {sha256}")
    
    try:
        if not file_content:
            result = {
                'verdict': 'error',
                'engine': 'yara',
                'score': 0,
                'details': 'No file content provided for scanning'
            }
        else:
            # Get compiled rules
            rules = get_compiled_rules()
            
            # Perform scan
            matches = rules.match(data=file_content)
            
            if matches:
                verdict = 'malicious'
                score = 1
                matched_rules = [match.rule for match in matches]
                details = f"Yara rules matched: {', '.join(matched_rules)}"
                
                # Get detailed match information
                match_details = []
                for match in matches:
                    match_info = {
                        'rule': match.rule,
                        'namespace': match.namespace,
                        'tags': list(match.tags),
                        'strings': []
                    }
                    for string_match in match.strings:
                        match_info['strings'].append({
                            'identifier': string_match.identifier,
                            'instances': len(string_match.instances)
                        })
                    match_details.append(match_info)
                
            else:
                verdict = 'clean'
                score = 0
                details = 'No Yara rules matched'
                match_details = []
            
            # Get file type information
            try:
                file_type = magic.from_buffer(file_content, mime=True)
            except Exception:
                file_type = 'unknown'
            
            result = {
                'verdict': verdict,
                'engine': 'yara',
                'score': score,
                'details': details,
                'matches': match_details,
                'file_type': file_type,
                'rules_count': len(rules)
            }
            
    except Exception as e:
        logger.error(f"Yara scan error: {str(e)}")
        result = {
            'verdict': 'error',
            'engine': 'yara',
            'score': 0,
            'details': f'Scan error: {str(e)}'
        }
    
    # Update database
    import asyncio
    async def update():
        async with SessionLocal() as session:
            stmt = select(Sample).where(Sample.sha256 == sha256)
            res = await session.execute(stmt)
            sample = res.scalar_one_or_none()
            if sample:
                # Update or merge with existing scan results
                existing_result = sample.scan_result or {}
                if isinstance(existing_result, dict):
                    existing_result['yara'] = result
                else:
                    existing_result = {'yara': result}
                
                sample.scan_result = existing_result
                sample.scan_status = 'finished'
                await session.commit()
                logger.info(f"Updated Yara scan result for {sha256}")
    
    asyncio.run(update())
    return result

@celery_app.task(name='yara.ping')
def ping():
    """Health check task for Yara scanner"""
    try:
        rules = get_compiled_rules()
        return {'status': 'healthy', 'engine': 'yara', 'rules_count': len(rules)}
    except Exception as e:
        return {'status': 'unhealthy', 'engine': 'yara', 'error': str(e)}