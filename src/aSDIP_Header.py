# this file is used to define function where a circular import might occur
import pyshark

def LFC(str):
    # literally here to save my hands this function is
    #used to create the object used to change variable names
    return pyshark.packet.fields.LayerFieldsContainer(str)