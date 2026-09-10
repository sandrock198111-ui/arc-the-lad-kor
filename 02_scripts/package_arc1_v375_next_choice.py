"""V375 fresh-original packaging with V374 exact-delta checks."""
import build_arc1_v375_next_choice as b
from package_arc1_v374_card_choice import main
if __name__=='__main__':
    main(build=b,stem='V375_NEXT_CHOICE_TEST',work='package_v375_next_choice',
         baseline='V374_CARD_CHOICE_TEST.bin',
         baseline_sha='9D98BC77225178908CFC4809D5460FB4AFBA72E105666CF929865DEE109D5182')
