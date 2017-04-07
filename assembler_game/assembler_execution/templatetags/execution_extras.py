from django import template

register = template.Library()


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

eflags_dict = {
    0: 'CF',
    2: 'PF',
    4: 'AF',
    6: 'ZF',
    7: 'SF',
    8: 'TF',
    9: 'IF',
    10: 'DF',
    11: 'OF',
    12: 'IOPL1',
    13: 'IOPL2',
    14: 'NT',
    16: 'RF',
    17: 'VM',
    18: 'AC',
    19: 'VIF',
    20: 'VIP',
    21: 'ID',
}


@register.filter
def translate_eflags(eflags):
    flags = []
    counter = 0
    for bit in bin(eflags)[:1:-1]:
        if bit == '1':
            if counter in eflags_dict:
                flags.append(eflags_dict[counter])
        counter += 1
    return " ".join(flags)


@register.filter
def line_count(string):
    return string.count("\n") + 1
