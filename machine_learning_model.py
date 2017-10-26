
import math
import os
import sys


class shell_detect :
    
    @staticmethod
    def read_file(file_path) :
        file = open(file_path)
        data = file.read()

        file.close()

        return data

    @staticmethod
    def code_word_to_vector(php_code) :
        filter_flag_list = ['@','[',']','(',')','{','}','\'','"',',',';','=','.','\t','\n','\r\n']
        keyword = ['$_GET','$_POST','$_REQUEST','$_COOKIE']

        for filter_flag_index in filter_flag_list :
            php_code = php_code.replace(filter_flag_index,' ')

        vector = php_code.split(' ')

        for index in range(len(vector)) :  #  filter $ variant
            if vector[index].startswith('$') and not vector[index] in keyword :
                vector[index] = ''
            elif vector[index] in keyword :
                vector[index] = '$'

        while vector.count('') :  #  filter empty item ..
            vector.remove('')

        return vector

    @staticmethod
    def load_and_train_model(data_set_path = 'shell') :
        file_list = os.listdir(data_set_path)
        shell_sample = {}          #  classfy set ..

        for file_index in file_list :
            try :
                file_information = file_index.split('-')
                classfy_type = file_information[0] + '-' + file_information[1] + '-' + file_information[2]
                php_code_vector = shell_detect.code_word_to_vector(shell_detect.read_file(data_set_path + '\\' + file_index))

                if not shell_sample.has_key(classfy_type) :
                    shell_sample[classfy_type] = []

                shell_sample[classfy_type].append(php_code_vector)
            except :
                print 'Error Shell Sample File !' , file_index
                print 'Sample File Name Format :'
                print ' normal-%shell_language%-%shell_type%-%shell_index%.php or '
                print ' shell-%shell_language%-%shell_type%-%shell_index%.php '

        return shell_sample
    
    def __init__(self,data_set_path = 'shell') :
        self.shell_sample = shell_detect.load_and_train_model(data_set_path)
    
    def try_classify(self,php_code) :
        php_code_vector = shell_detect.code_word_to_vector(php_code)
        alpha = 1
        p_list = {}

        #print 'Debug for try_classify : ' ,php_code_vector

        for key_index in self.shell_sample.keys() :
            max_p_value = 0

            for shell_sample_index in self.shell_sample[key_index] :
                found_vector_in_shell_sample_count = 0

                for php_code_vector_index in php_code_vector :
                    if php_code_vector_index in shell_sample_index :
                        found_vector_in_shell_sample_count += shell_sample_index.count(php_code_vector_index)

                p_value = (found_vector_in_shell_sample_count + alpha) / float(len(shell_sample_index) * 2 + alpha)

                #print shell_sample_index , p_value

                if p_value >= max_p_value :
                    max_p_value = p_value

            p_list[key_index] = max_p_value

            #print key_index ,p_list[key_index]

        max_p_value = 0
        max_p_type_name = ''

        for p_type_name_index in p_list.keys() :
            p_value = p_list[p_type_name_index]

            if p_value >= max_p_value :
                max_p_value = p_value
                max_p_type_name = p_type_name_index

        #print php_code , max_p_type_name , max_p_value

        return max_p_type_name

    
if __name__ == '__main__' :
    model = shell_detect()
    
    if 2 == len(sys.argv) :
        print 'Shell Type :' , model.try_classify(shell_detect.read_file(sys.argv[1]))
    else :
        print 'Test Sample ..'
        print 'Shell Type :' , model.try_classify('<?php eval($_GET["exp"]); ?>')
        print 'Shell Type :' , model.try_classify('<?php assert($_GET["exp"]); ?>')
        print 'Shell Type :' , model.try_classify('<?php system($_GET["exp"]); ?>')
        print 'Shell Type :' , model.try_classify('<?php systen("ifconfig"); ?>')
        print 'Shell Type :' , model.try_classify('<?php echo "123"; ?>')
        print 'Shell Type :' , model.try_classify('<?php $b=1+1; ?>')
        print 'Shell Type :' , model.try_classify('<?php phpinfo(); ?>')
        print 'Shell Type :' , model.try_classify('<?php $a=create_function(\'\',\'ev\',\'al\'.\'($\'.\'_GET["e"]);\'); $a(); ?>')
        print 'Shell Type :' , model.try_classify('<?php include($_COOKIE[\'s\']); ?>')
        print 'Shell Type :' , model.try_classify('<?php require_once($_POST[\'s\']); ?>')