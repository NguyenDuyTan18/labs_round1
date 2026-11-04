"""Persist tick state and challenge rows in one SQLite attached-db transaction."""
import json
import re
import secrets
import sqlite3

TASKS = ('sqli', 'idor', 'upload', 'jwt', 'backup')


def current_round(auth_db, catalog_db, initial_flags, now, interval):
    with sqlite3.connect(auth_db, timeout=15) as con:
        con.execute('ATTACH DATABASE ? AS catalog', (str(catalog_db),))
        con.execute('BEGIN IMMEDIATE')
        con.execute('CREATE TABLE IF NOT EXISTS fashion_round (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT)')
        row = con.execute('SELECT payload FROM fashion_round WHERE id=1').fetchone()
        state = json.loads(row[0]) if row else {
            'tick': 0, 'started': now, 'flags': initial_flags,
            'locators': {'sqli': 'supplier_notes', 'idor': 1,
                         'upload': '../private/design-brief.txt', 'jwt': 'welcome',
                         'backup': '/backup/shop.sql.bak'}}
        elapsed = max(0, int((now - state['started']) // interval))
        if elapsed:
            state['tick'] += elapsed
            state['started'] += elapsed * interval
            state['flags'] = {t: 'FLAG{' + secrets.token_hex(16) + '}' for t in TASKS}
            suffix = str(state['tick']) + '-' + secrets.token_hex(4)
            state['locators'] = {
                'sqli': 'supplier_notes_' + suffix.replace('-', '_'),
                'idor': 3000 + state['tick'] * 100 + secrets.randbelow(100),
                'upload': '../private/design-' + suffix + '.txt',
                'jwt': 'offer-' + suffix,
                'backup': '/backup/export-' + suffix + '.sql.bak'}
        if not row or elapsed:
            # The synthetic customer cannot log in. Keep real customer IDs stable.
            con.execute('UPDATE customers SET id=?,note=? WHERE username=?',
                        (state['locators']['idor'], state['flags']['idor'], 'linh-vip'))
            # Only generated identifiers enter DDL; flag values remain parameters.
            tables = con.execute("SELECT name FROM catalog.sqlite_master WHERE type='table'").fetchall()
            for (name,) in tables:
                if re.fullmatch(r'supplier_notes(?:_[0-9]+_[a-f0-9]{8})?', name):
                    con.execute('DROP TABLE catalog."' + name + '"')
            name = state['locators']['sqli']
            if not re.fullmatch(r'supplier_notes(?:_[0-9]+_[a-f0-9]{8})?', name):
                raise ValueError('Invalid supplier table in round state')
            con.execute('CREATE TABLE catalog."' + name + '" (secret TEXT)')
            con.execute('INSERT INTO catalog."' + name + '" VALUES(?)', (state['flags']['sqli'],))
            con.execute('INSERT OR REPLACE INTO fashion_round VALUES(1,?)', (json.dumps(state),))
    return state
