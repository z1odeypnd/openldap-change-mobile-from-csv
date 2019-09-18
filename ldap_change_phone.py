#!/usr/bin/env python2
import csv
import datetime
import getpass
import logging
import os
import re
import sys
import subprocess


def print_usage():
    print("""
    Usage: 
    python2 %s file [mode]
    args:
        file        path to csv file
        mode        "backup" or "rollback" (default: backup)
    Examples:
        python2 %s /tmp/change_phones.csv
        python2 %s /tmp/change_phones.csv backup
        python2 %s /tmp/change_phones.csv rollback""" % (os.path.basename(__file__), __file__, __file__, __file__))
    return 1


def which_cmd(command_name):
    """
    search linux binaries in OS $PATH variable
    """
    for each_path in os.getenv("PATH").split(os.path.pathsep):
        full_path = each_path + os.sep + command_name
        if os.path.exists(full_path):
            command_path = full_path
            # Return first founded bin
            return command_path
    return False


def init_checks(csv_file, required_binaries):
    logging.info("Initial checks...")
    logging.debug("Search csv file '%s'..." % csv_file)
    if not os.path.exists(csv_file):
        logging.error("csv file '%s' not exist!" % csv_file)
        return False

    for req_bin in required_binaries:
        if not which_cmd(req_bin):
            logging.error("Required binary file '%s' not found in OS PATH variable!" % req_bin)
            logging.debug("PATH variable: %s" % os.getenv("PATH"))
            return False

    return True


def check_csv_fields(csv_dict):
    try:
        #
        # Check csv field names
        field1, field2, field3 = csv_dict[0]['USER_NAME'], csv_dict[0]['NEW_DATA_PHONE'], csv_dict[0]['OLD_DATA_PHONE']
        return True
    except KeyError as Ex:
        logging.exception("Not found expected fields: 'USER_NAME', 'NEW_DATA_PHONE', 'OLD_DATA_PHONE'!")
        return False


def check_ascsii(csv_string):
    string_to_check = csv_string['USER_NAME']
    check_flag = True
    for char in string_to_check:
        if ord(char) < 128:
            check_flag = True
        else:
            logging.warn("Field 'USER_NAME' contains incorrect symbol '%s' in "
                         "string '%s'" % (char.decode('latin1'), string_to_check.decode('latin1')))
            check_flag = False
            break
    return check_flag


def read_csv(csv_file):
    csv_dict = []
    csv_valid_dict = []
    csv_invalid_dict = []
    logging.info("Read csv file %s" % csv_file)
    try:
        with open(csv_file) as csvfile:
            csv_dialect = csv.Sniffer().sniff(csvfile.read(1024))
            csvfile.seek(0)
            reader = csv.DictReader(csvfile, dialect=csv_dialect)
            field = reader.fieldnames
            for row in reader:
                csv_dict.extend([row])
        logging.debug("csv entries list:\n%s" % csv_dict)
        if not check_csv_fields(csv_dict):
            return [None, None]
        for csv_string in csv_dict:
            if check_ascsii(csv_string):
                csv_valid_dict.extend([csv_string])
            else:
                csv_invalid_dict.extend([csv_string])
                logging.debug("csv string failed: %s" % csv_string)
        return [csv_valid_dict, csv_invalid_dict]
    except:
        logging.exception("csv reader failed!")
        return [None, None]


def ldap_search_users(csv_dict, ldap_bind_dn, ldap_manager_dn, ldapsearch_linux_bin):
    ldap_dict = []
    ldap_not_found_dict = []
    logging.info("Search users in LDAP...")
    ldap_password = getpass.getpass('Enter LDAP password: ')
    for csv_row in csv_dict:
        result = None
        user_uid = csv_row['USER_NAME']
        cmd = ldapsearch_linux_bin + ' -Z -H ldapi:/// -D "' + ldap_manager_dn + '" -w ' + ldap_password + ' -b "' + \
              ldap_bind_dn + '" -LLL "(uid=' + user_uid + ')" dn'
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.wait()
        pstdout = proc.stdout.read()
        pstderr = proc.stderr.read()
        if pstdout:
            result = re.search('cn=.*', pstdout)
        if result:
            logging.debug("Append DN '%s' for user '%s'" % (result.group(0), user_uid))
            csv_row['USER_DN'] = result.group(0)
            ldap_dict.append(csv_row)
        else:
            logging.warn("DN for user '%s' not found! Skip." % user_uid)
            ldap_not_found_dict.append(csv_row)
        if proc.returncode != 0:
            logging.error("process stderr: %s" % pstderr)
            logging.error("Search users failed!")
    logging.debug("LDAP users list:\n%s", ldap_dict)
    # Clear ldap password
    ldap_password = None
    return [ldap_dict, ldap_not_found_dict]


def ldap_backup(ldap_backup_file, slapcat_linux_bin):
    logging.info("Create backup into ldap_backup_file...")
    cmd = slapcat_linux_bin + " > " + ldap_backup_file
    open(ldap_backup_file, 'w').close()
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    pstdout = proc.stdout.read()
    pstderr = proc.stderr.read()
    logging.debug("process stdout:\n%s" % pstdout)
    if proc.returncode != 0:
        logging.error("process stderr:\n%s" % pstderr)
        logging.error("Backup failed!")
        return False
    return True


def write_ldifs(users_dict, ldif_replace_file, ldif_rollback_file):
    #
    # Create|clear LDIF-file
    open(ldif_replace_file, 'w').close()
    open(ldif_rollback_file, 'w').close()
    logging.info("Write LDIFs...")
    for csv_row in users_dict:
        ldif_mod_entry = """dn: %s
changetype: modify
replace: mobile
mobile: %s

""" % (csv_row['USER_DN'], csv_row['NEW_DATA_PHONE'])
        ldif_rollback_entry = """dn: %s
changetype: modify
replace: mobile
mobile: %s

""" % (csv_row['USER_DN'], csv_row['OLD_DATA_PHONE'])

        try:
            logging.debug("\nWrite LDIF replace entry:\n%s" % (ldif_mod_entry))
            with open(ldif_replace_file, 'a') as fm:
                fm.write(ldif_mod_entry)
            logging.debug("\nWrite LDIF rollback entry:\n%s" % (ldif_rollback_entry))
            with open(ldif_rollback_file, 'a') as fb:
                fb.write(ldif_rollback_entry)
        except:
            logging.exception("LDIF writen with errors!")
            return False

    return True


def ldap_apply_ldif(ldif_file, ldap_manager_dn, ldapmodify_linux_bin):
    # Request ldap password
    ldap_password = getpass.getpass('Enter LDAP password: ')
    logging.info("Apply LDIF file '%s'..." % ldif_file)
    cmd = ldapmodify_linux_bin + ' -Z -c -H ldapi:/// -w ' + ldap_password + ' -D "' + ldap_manager_dn + \
          '" -f ' + ldif_file
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    # Clear ldap password
    ldap_password = None
    cmd = None
    pstdout = proc.stdout.read()
    pstderr = proc.stderr.read()
    logging.debug("process stdout:\n%s" % pstdout)
    if proc.returncode != 0:
        logging.error("process stderr:\n%s" % pstderr)
        logging.error("Apply LDIF finished with errors!")
        return False
    return True


def user_question(question_text):
    while True:
        usr_answer = raw_input("%s [y/n]: " % question_text)
        if not usr_answer:
            print("Please, type answer.")
            continue
        if usr_answer.lower() == 'y':
            break
        elif usr_answer.lower() == 'n':
            return False
        else:
            print("Wrong answer! Try again.")
    return True


def users_modify(ldif_file, ldap_manager_dn, ldapmodify_linux_bin):
    with open(ldif_file, 'r') as lf:
        text = lf.read()
        logging.debug("LDIF content:\n%s" % text)
        print("LDIF content:\n%s\n\n!!! Please, check LDIF content above, before apply!" % text)
    #
    # Ask user before apply LDIF
    question_text = 'Apply LDIF?'
    if not user_question(question_text):
        print("Exit.")
        return False

    if ldap_apply_ldif(ldif_file, ldap_manager_dn, ldapmodify_linux_bin):
        return True
    return True


def main():
    # logging.basicConfig(format=u'[%(asctime)s][%(levelname)-7s][PID:%(process)d][TID:%(thread)d] %(funcName)s.%('
    #                            u'lineno)d: %(message)s', level=logging.DEBUG, stream=sys.stdout)
    required_binaries = ['ldapsearch', 'ldapmodify', 'slapcat']
    cur_date = datetime.datetime.today().strftime('%Y-%m-%d')
    cur_timestamp = datetime.datetime.today().strftime('%Y-%m-%d_%H-%M-%S')
    script_dir = os.path.dirname(__file__)
    script_basename = os.path.basename(os.path.splitext(__file__)[0])
    log_file_name = script_basename + ".log"
    log_file = os.path.join(script_dir, log_file_name)
    if not os.path.exists(log_file):
        open(log_file, 'w').close()
    logging.basicConfig(format=u'[%(asctime)s][%(levelname)-7s][PID:%(process)d] %(funcName)s.%('
                               u'lineno)d: %(message)s', level=logging.INFO, filename=log_file)
    ldif_replace_file_name = script_basename + "_replace_" + cur_date + ".ldif"
    ldif_replace_file = os.path.join(script_dir, ldif_replace_file_name)
    ldif_rollback_file_name = script_basename + "_rollback_" + cur_date + ".ldif"
    ldif_rollback_file = os.path.join(script_dir, ldif_rollback_file_name)
    ldap_backup_file_name = script_basename + "_backup_" + cur_timestamp + ".ldif"
    ldap_backup_file = os.path.join(script_dir, ldap_backup_file_name)
    ldap_bind_dn = "ou=Users,dc=example,dc=com"
    ldap_manager_dn = "cn=Manager,dc=example,dc=com"

    try:
        csv_file = os.path.abspath(sys.argv[1])
    except:
        logging.error("First argument should be csv file!")
        print_usage()
        return 1
    #
    # Run initial checks (csv file exist, required binaries exists)
    if not init_checks(csv_file, required_binaries):
        return 1
    #
    # Search required binaries
    ldapsearch_linux_bin = which_cmd('ldapsearch')
    ldapmodify_linux_bin = which_cmd('ldapmodify')
    slapcat_linux_bin = which_cmd('slapcat')
    #
    # Check script mode
    try:
        script_mode = sys.argv[2]
    except IndexError:
        script_mode = 'backup'
    #
    # Run script in backup mode
    if script_mode == 'backup':
        csv_valid_dict, csv_invalid_dict = read_csv(csv_file)
        if not csv_valid_dict:
            logging.error("Not found correct csv strings in file '%s'." % csv_file)
            return 1
        #
        # Search users in LDAP
        users_dict, ldap_not_found_dict = ldap_search_users(csv_valid_dict, ldap_bind_dn, ldap_manager_dn,
                                                            ldapsearch_linux_bin)

        if ldap_not_found_dict:
            for csv_user in ldap_not_found_dict:
                print("User '%s' from csv not found in LDAP!" % csv_user['USER_NAME'])
            question_text = 'Continue?'
            if not user_question(question_text):
                print("Exit.")
                return 1

        if csv_invalid_dict:
            for csv_string in csv_invalid_dict:
                try:
                    print(
                        "Field 'USER_NAME' contains not ASCII symbols! String will be skipped.\nString: "
                        "'%s'\n'USER_NAME' = '%s'" % (csv_string, csv_string['USER_NAME'].decode('latin1')))
                except:
                    logging.exception("Failed to print incorrect user!")
            question_text = 'Continue?'
            if not user_question(question_text):
                print("Exit.")
                return 1

        if users_dict:
            if not ldap_backup(ldap_backup_file, slapcat_linux_bin):
                return 1
            if not write_ldifs(users_dict, ldif_replace_file, ldif_rollback_file):
                return 1
            if not users_modify(ldif_replace_file, ldap_manager_dn, ldapmodify_linux_bin):
                return 1

        if ldap_not_found_dict:
            for csv_user in ldap_not_found_dict:
                logging.warn("User '%s' not found in LDAP!" % csv_user['USER_NAME'])

    elif script_mode == 'rollback':
        if not users_modify(ldif_rollback_file, ldap_manager_dn, ldapmodify_linux_bin):
            return 1
    else:
        logging.error("Wrong mode '%s'!" % script_mode)
        print_usage()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())